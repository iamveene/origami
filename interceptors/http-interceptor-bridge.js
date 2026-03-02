// Origami HTTP Interceptor Bridge -- ISOLATED World Relay
// Listens for window.postMessage from the MAIN world interceptor and relays
// entries to the background service worker via chrome.runtime.sendMessage.
// Uses postMessage instead of CustomEvent because CustomEvent.detail is NOT
// reliably accessible across MAIN/ISOLATED worlds in Chrome.

(function() {
  'use strict';

  // Guard against double-injection
  if (window.__origamiHttpBridgeInstalled) return;
  window.__origamiHttpBridgeInstalled = true;

  // Listen for captured HTTP entries from MAIN world (via postMessage)
  window.addEventListener('message', function(e) {
    if (e.source !== window) return;
    if (!e.data || e.data.__origamiType !== 'http-captured') return;

    try {
      var entry = e.data.entry;
      if (!entry) return;

      // Add tab context
      entry.tabUrl = location.href;
      entry.timestamp = Date.now();

      console.log('Origami Bridge: relaying entry', entry.method, entry.url);
      chrome.runtime.sendMessage({
        action: 'httpHistoryEntry',
        entry: entry
      }).then(function() {
        console.log('Origami Bridge: entry relayed OK');
      }).catch(function(err) {
        console.warn('Origami Bridge: relay failed', err && err.message);
      });
    } catch (err) {
      console.warn('Origami Bridge: exception', err && err.message);
    }
  });

  // On load, check if capture is enabled and relay state to MAIN world
  chrome.runtime.sendMessage({ action: 'getHttpHistoryState' }, function(response) {
    if (chrome.runtime.lastError) {
      console.warn('Origami Bridge: state request failed', chrome.runtime.lastError.message);
      return;
    }
    console.log('Origami Bridge: state from background', JSON.stringify(response));
    if (response) {
      window.postMessage({
        __origamiType: 'http-control',
        enabled: response.enabled || false,
        scope: response.scope || 'same-origin'
      }, '*');
    }
  });

  // Listen for control messages from background (enable/disable/scope changes)
  chrome.runtime.onMessage.addListener(function(request) {
    if (request.action === 'httpCaptureControl') {
      window.postMessage({
        __origamiType: 'http-control',
        enabled: request.enabled,
        scope: request.scope
      }, '*');
    }
  });

})();
