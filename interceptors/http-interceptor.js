// Origami HTTP Interceptor -- MAIN World Script
// Monkey-patches fetch, XMLHttpRequest, navigator.sendBeacon, and form.submit
// to capture all JS-initiated HTTP traffic for the HTTP History feature.
// Uses window.postMessage to relay data to the ISOLATED world bridge
// (CustomEvent.detail is NOT reliably accessible across MAIN/ISOLATED worlds).

(function() {
  'use strict';

  // Guard against double-injection
  if (window.__origamiHttpInterceptorInstalled) return;
  window.__origamiHttpInterceptorInstalled = true;

  // Capture state -- controlled by bridge messages
  let captureEnabled = false;
  let captureScope = 'same-origin';
  const pageOrigin = location.origin;
  const pageDomain = location.hostname;

  // Listen for enable/disable from the ISOLATED world bridge (via postMessage)
  window.addEventListener('message', function(e) {
    if (e.source !== window) return;
    if (!e.data || e.data.__origamiType !== 'http-control') return;
    if (typeof e.data.enabled === 'boolean') {
      captureEnabled = e.data.enabled;
    }
    if (e.data.scope) {
      captureScope = e.data.scope;
    }
  });

  const MAX_BODY_SIZE = 512 * 1024; // 500KB
  const EXCLUDE_MIME = ['image/', 'font/', 'video/', 'audio/'];
  const CREDENTIAL_FIELDS = /\b(password|passwd|pwd|secret|token|credential|api_key|apikey|auth)\b/i;

  function shouldCapture(url) {
    if (!captureEnabled) return false;
    try {
      const parsed = new URL(url, location.href);
      if (!['http:', 'https:'].includes(parsed.protocol)) return false;
      if (captureScope === 'same-origin') {
        return parsed.origin === pageOrigin;
      } else if (captureScope === 'domain-subdomains') {
        return parsed.hostname === pageDomain || parsed.hostname.endsWith('.' + pageDomain);
      }
      // 'all' scope
      return true;
    } catch (e) {
      return false;
    }
  }

  function shouldExcludeMime(contentType) {
    if (!contentType) return false;
    const lower = contentType.toLowerCase();
    return EXCLUDE_MIME.some(prefix => lower.includes(prefix));
  }

  function truncateBody(body) {
    if (!body || typeof body !== 'string') return { text: body || '', truncated: false };
    if (body.length > MAX_BODY_SIZE) {
      return { text: body.substring(0, MAX_BODY_SIZE), truncated: true };
    }
    return { text: body, truncated: false };
  }

  function extractDomain(url) {
    try { return new URL(url, location.href).hostname; } catch (e) { return ''; }
  }

  function extractPath(url) {
    try { return new URL(url, location.href).pathname; } catch (e) { return ''; }
  }

  function detectCredentials(body) {
    if (!body || typeof body !== 'string') return false;
    return CREDENTIAL_FIELDS.test(body);
  }

  function headersToObject(headers) {
    const obj = {};
    if (headers instanceof Headers) {
      headers.forEach((value, key) => { obj[key] = value; });
    } else if (typeof headers === 'object' && headers !== null) {
      if (Array.isArray(headers)) {
        headers.forEach(([key, value]) => { obj[key] = value; });
      } else {
        Object.assign(obj, headers);
      }
    }
    return obj;
  }

  function serializeBody(body) {
    if (!body) return '';
    if (typeof body === 'string') return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof FormData) {
      const parts = [];
      body.forEach((value, key) => {
        if (value instanceof File) {
          parts.push(key + '=[File: ' + value.name + ', ' + value.size + ' bytes]');
        } else {
          parts.push(key + '=' + value);
        }
      });
      return parts.join('&');
    }
    if (body instanceof Blob) return '[Blob: ' + body.size + ' bytes]';
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
      const size = body.byteLength || body.buffer?.byteLength || 0;
      return '[Binary: ' + size + ' bytes]';
    }
    try { return JSON.stringify(body); } catch (e) { return String(body); }
  }

  function dispatch(entry) {
    try {
      // Use postMessage for reliable MAIN -> ISOLATED world communication
      window.postMessage({
        __origamiType: 'http-captured',
        entry: entry
      }, '*');
    } catch (e) {
      // Silently fail -- don't break page functionality
    }
  }

  // =========================================================================
  // Patch fetch()
  // =========================================================================
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    const url = (input instanceof Request) ? input.url : String(input);
    if (!shouldCapture(url)) {
      return originalFetch.apply(this, arguments);
    }

    const method = (init && init.method) || (input instanceof Request ? input.method : 'GET');
    let requestHeaders = {};
    if (init && init.headers) {
      requestHeaders = headersToObject(init.headers);
    } else if (input instanceof Request) {
      requestHeaders = headersToObject(input.headers);
    }

    let requestBodyStr = '';
    if (init && init.body) {
      requestBodyStr = serializeBody(init.body);
    } else if (input instanceof Request && input.body) {
      // Cannot read Request body without consuming it; record as unknown
      requestBodyStr = '[Request body]';
    }

    const startTime = performance.now();

    return originalFetch.apply(this, arguments).then(function(response) {
      const timing = Math.round(performance.now() - startTime);
      const contentType = response.headers.get('content-type') || '';

      if (shouldExcludeMime(contentType)) {
        dispatch({
          source: 'fetch',
          method: method.toUpperCase(),
          url: url,
          domain: extractDomain(url),
          path: extractPath(url),
          requestHeaders: requestHeaders,
          requestBody: requestBodyStr,
          requestBodySize: requestBodyStr.length,
          status: response.status,
          statusText: response.statusText,
          contentType: contentType,
          responseHeaders: headersToObject(response.headers),
          responseBody: '[excluded: ' + contentType + ']',
          responseBodySize: 0,
          truncated: false,
          timing: timing,
          hasCredentials: detectCredentials(requestBodyStr)
        });
        return response;
      }

      // Clone response to read body without consuming original
      const clone = response.clone();
      clone.text().then(function(bodyText) {
        const body = truncateBody(bodyText);
        dispatch({
          source: 'fetch',
          method: method.toUpperCase(),
          url: url,
          domain: extractDomain(url),
          path: extractPath(url),
          requestHeaders: requestHeaders,
          requestBody: requestBodyStr,
          requestBodySize: requestBodyStr.length,
          status: response.status,
          statusText: response.statusText,
          contentType: contentType,
          responseHeaders: headersToObject(response.headers),
          responseBody: body.text,
          responseBodySize: bodyText.length,
          truncated: body.truncated,
          timing: timing,
          hasCredentials: detectCredentials(requestBodyStr)
        });
      }).catch(function() {
        // Body read failed -- still record the request
        dispatch({
          source: 'fetch',
          method: method.toUpperCase(),
          url: url,
          domain: extractDomain(url),
          path: extractPath(url),
          requestHeaders: requestHeaders,
          requestBody: requestBodyStr,
          requestBodySize: requestBodyStr.length,
          status: response.status,
          statusText: response.statusText,
          contentType: contentType,
          responseHeaders: headersToObject(response.headers),
          responseBody: '[body read error]',
          responseBodySize: 0,
          truncated: false,
          timing: timing,
          hasCredentials: detectCredentials(requestBodyStr)
        });
      });

      return response;
    }).catch(function(error) {
      const timing = Math.round(performance.now() - startTime);
      dispatch({
        source: 'fetch',
        method: method.toUpperCase(),
        url: url,
        domain: extractDomain(url),
        path: extractPath(url),
        requestHeaders: requestHeaders,
        requestBody: requestBodyStr,
        requestBodySize: requestBodyStr.length,
        status: 0,
        statusText: 'Network Error',
        contentType: '',
        responseHeaders: {},
        responseBody: error.message || 'fetch failed',
        responseBodySize: 0,
        truncated: false,
        timing: timing,
        hasCredentials: detectCredentials(requestBodyStr)
      });
      throw error;
    });
  };

  // =========================================================================
  // Patch XMLHttpRequest
  // =========================================================================
  const OriginalXHR = window.XMLHttpRequest;
  const xhrProto = OriginalXHR.prototype;
  const originalOpen = xhrProto.open;
  const originalSend = xhrProto.send;
  const originalSetRequestHeader = xhrProto.setRequestHeader;

  xhrProto.open = function(method, url) {
    this._origami = {
      method: (method || 'GET').toUpperCase(),
      url: String(url),
      requestHeaders: {},
      startTime: 0
    };
    return originalOpen.apply(this, arguments);
  };

  xhrProto.setRequestHeader = function(name, value) {
    if (this._origami) {
      this._origami.requestHeaders[name] = value;
    }
    return originalSetRequestHeader.apply(this, arguments);
  };

  xhrProto.send = function(body) {
    if (!this._origami || !shouldCapture(this._origami.url)) {
      return originalSend.apply(this, arguments);
    }

    const meta = this._origami;
    meta.startTime = performance.now();
    meta.requestBody = serializeBody(body);

    const xhr = this;
    const onDone = function() {
      const timing = Math.round(performance.now() - meta.startTime);
      const contentType = xhr.getResponseHeader('content-type') || '';

      // Parse response headers
      const rawHeaders = xhr.getAllResponseHeaders() || '';
      const responseHeaders = {};
      rawHeaders.trim().split(/[\r\n]+/).forEach(function(line) {
        const parts = line.split(': ');
        if (parts.length >= 2) {
          const key = parts.shift();
          responseHeaders[key] = parts.join(': ');
        }
      });

      let responseBody = '';
      let responseBodySize = 0;
      let truncated = false;

      if (!shouldExcludeMime(contentType)) {
        try {
          const text = xhr.responseType === '' || xhr.responseType === 'text'
            ? xhr.responseText
            : '[binary: ' + xhr.responseType + ']';
          const body = truncateBody(text);
          responseBody = body.text;
          responseBodySize = text.length;
          truncated = body.truncated;
        } catch (e) {
          responseBody = '[body read error]';
        }
      } else {
        responseBody = '[excluded: ' + contentType + ']';
      }

      dispatch({
        source: 'xhr',
        method: meta.method,
        url: meta.url,
        domain: extractDomain(meta.url),
        path: extractPath(meta.url),
        requestHeaders: meta.requestHeaders,
        requestBody: meta.requestBody,
        requestBodySize: meta.requestBody.length,
        status: xhr.status,
        statusText: xhr.statusText,
        contentType: contentType,
        responseHeaders: responseHeaders,
        responseBody: responseBody,
        responseBodySize: responseBodySize,
        truncated: truncated,
        timing: timing,
        hasCredentials: detectCredentials(meta.requestBody)
      });
    };

    xhr.addEventListener('loadend', onDone);

    return originalSend.apply(this, arguments);
  };

  // =========================================================================
  // Patch navigator.sendBeacon()
  // =========================================================================
  if (navigator.sendBeacon) {
    const originalBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) {
      if (shouldCapture(url)) {
        const bodyStr = serializeBody(data);
        dispatch({
          source: 'beacon',
          method: 'POST',
          url: String(url),
          domain: extractDomain(url),
          path: extractPath(url),
          requestHeaders: {},
          requestBody: bodyStr,
          requestBodySize: bodyStr.length,
          status: 0,
          statusText: 'Beacon (fire-and-forget)',
          contentType: '',
          responseHeaders: {},
          responseBody: '',
          responseBodySize: 0,
          truncated: false,
          timing: 0,
          hasCredentials: detectCredentials(bodyStr)
        });
      }
      return originalBeacon(url, data);
    };
  }

  // =========================================================================
  // Patch HTMLFormElement.prototype.submit and form submit events
  // =========================================================================
  const originalFormSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    captureFormSubmission(this);
    return originalFormSubmit.apply(this, arguments);
  };

  // Also capture submit events (covers user-triggered submits)
  document.addEventListener('submit', function(e) {
    if (e.target && e.target.tagName === 'FORM') {
      captureFormSubmission(e.target);
    }
  }, true);

  function captureFormSubmission(form) {
    const action = form.action || location.href;
    if (!shouldCapture(action)) return;

    const method = (form.method || 'GET').toUpperCase();
    const formData = new FormData(form);
    const bodyStr = serializeBody(formData);

    // Detect credential fields specifically from form inputs
    let hasCredentials = false;
    const inputs = form.querySelectorAll('input');
    for (let i = 0; i < inputs.length; i++) {
      if (inputs[i].type === 'password' || CREDENTIAL_FIELDS.test(inputs[i].name)) {
        hasCredentials = true;
        break;
      }
    }

    dispatch({
      source: 'form',
      method: method,
      url: action,
      domain: extractDomain(action),
      path: extractPath(action),
      requestHeaders: { 'Content-Type': form.enctype || 'application/x-www-form-urlencoded' },
      requestBody: bodyStr,
      requestBodySize: bodyStr.length,
      status: 0,
      statusText: 'Form Submission (navigating)',
      contentType: '',
      responseHeaders: {},
      responseBody: '',
      responseBodySize: 0,
      truncated: false,
      timing: 0,
      hasCredentials: hasCredentials
    });
  }

})();
