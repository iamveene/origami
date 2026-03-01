// Origami Technology Fingerprinter
// Detects frameworks, libraries, and technologies used on a website

class TechnologyFingerprinter {
  constructor() {
    this.detected = {
      frameworks: [],
      libraries: [],
      backend: [],
      cdn: [],
      analytics: [],
      security: [],
      buildTools: [],
      hosting: []
    };
  }

  // Main fingerprinting function
  async fingerprint(document, window) {
    this.detected = {
      frameworks: [],
      libraries: [],
      backend: [],
      cdn: [],
      analytics: [],
      security: [],
      buildTools: [],
      hosting: []
    };

    // Check window globals
    this.checkGlobals(window);

    // Check DOM attributes and patterns
    this.checkDOM(document);

    // Check HTTP headers (if available)
    await this.checkHeaders();

    // Check scripts
    this.checkScripts(document);

    // Check meta tags
    this.checkMetaTags(document);

    // Check cookies
    this.checkCookies();

    // Analyze build patterns
    this.analyzeBuildPatterns(document);

    // Remove cross-category duplicates
    this.deduplicateAcrossCategories();

    return this.detected;
  }

  // Normalize a technology name to a canonical form for deduplication
  // e.g., "React.js", "ReactJS", "react" all become "react"
  normalizeTechName(name) {
    return name
      .toLowerCase()
      .replace(/\.js$/i, '')   // Remove trailing .js
      .replace(/js$/i, '')      // Remove trailing js (e.g., "ReactJS" -> "React" -> "react")
      .replace(/[.\-_\s]/g, '') // Remove dots, dashes, underscores, spaces
      .trim();
  }

  // Remove same technology appearing in multiple categories
  deduplicateAcrossCategories() {
    // Preferred category for technologies that could appear in multiple
    const categoryPriority = {
      'Next.js': 'frameworks', 'Nuxt.js': 'frameworks', 'Gatsby': 'frameworks',
      'React': 'frameworks', 'Vue.js': 'frameworks', 'Angular': 'frameworks',
      'Svelte': 'frameworks', 'SvelteKit': 'frameworks',
      'Lit': 'frameworks', 'Stencil': 'frameworks', 'Polymer': 'frameworks',
      'Ember.js': 'frameworks', 'Backbone.js': 'frameworks', 'Preact': 'frameworks',
      'Alpine.js': 'frameworks', 'Remix': 'frameworks', 'SolidJS': 'frameworks',
      'HTMX': 'frameworks', 'Eleventy': 'frameworks', 'Qwik': 'frameworks',
      'Cloudflare': 'cdn', 'Fastly': 'cdn', 'Akamai': 'cdn', 'AWS CloudFront': 'cdn',
      'Express.js': 'backend', 'PHP': 'backend', 'ASP.NET': 'backend',
      'WordPress': 'backend', 'Drupal': 'backend', 'Shopify': 'backend',
      'Magento': 'backend', 'PrestaShop': 'backend', 'Ghost': 'backend',
      'Webflow': 'backend', 'Framer': 'backend', 'Bubble': 'backend',
      'jQuery': 'libraries', 'Lodash': 'libraries', 'D3.js': 'libraries',
      'Highcharts': 'libraries', 'ApexCharts': 'libraries', 'Plotly': 'libraries',
      'TinyMCE': 'libraries', 'CKEditor': 'libraries', 'Quill': 'libraries',
      'Stripe': 'libraries', 'PayPal': 'libraries', 'Braintree': 'libraries',
      'Firebase': 'libraries', 'Supabase': 'libraries', 'AWS Amplify': 'libraries',
      'Mapbox': 'libraries', 'Leaflet': 'libraries', 'Google Maps': 'libraries',
      'Socket.IO': 'libraries', 'Pusher': 'libraries', 'Ably': 'libraries',
      'Swiper': 'libraries', 'Lottie': 'libraries', 'Hammer.js': 'libraries',
      'MobX': 'libraries', 'Redux': 'libraries', 'Zustand': 'libraries',
      'Bootstrap': 'libraries', 'Material UI': 'libraries', 'Chakra UI': 'libraries',
      'Ant Design': 'libraries', 'Semantic UI': 'libraries', 'Tailwind CSS': 'libraries',
      'Webpack': 'buildTools', 'Vite': 'buildTools', 'Parcel': 'buildTools',
      'Google Analytics': 'analytics', 'Google Tag Manager': 'analytics',
      'Sentry': 'analytics', 'LogRocket': 'analytics', 'Datadog RUM': 'analytics',
      'Intercom': 'analytics', 'Zendesk': 'analytics', 'Drift': 'analytics',
      'Matomo': 'analytics', 'Plausible': 'analytics', 'Amplitude': 'analytics',
      'Clarity': 'analytics', 'FullStory': 'analytics', 'Heap': 'analytics',
      'reCAPTCHA': 'security', 'hCaptcha': 'security', 'Turnstile': 'security'
    };

    // Deterministic fallback: if no explicit preference, prefer more specific categories
    const categoryRank = {
      'frameworks': 0, 'backend': 1, 'libraries': 2, 'cdn': 3,
      'analytics': 4, 'security': 5, 'buildTools': 6, 'hosting': 7
    };

    // First: normalize names within each category to merge duplicates like "React.js" and "React"
    const seen = new Map(); // normalized name -> { canonicalName, category, version }
    const categories = Object.keys(this.detected);

    // First pass: collect all techs and their preferred categories, using normalized names
    for (const category of categories) {
      for (const tech of this.detected[category]) {
        const normalizedKey = this.normalizeTechName(tech.name);
        if (!seen.has(normalizedKey)) {
          seen.set(normalizedKey, { canonicalName: tech.name, category, version: tech.version });
        } else {
          const existing = seen.get(normalizedKey);
          // Prefer the name that has an explicit priority entry
          const canonicalName = categoryPriority[tech.name] ? tech.name :
            (categoryPriority[existing.canonicalName] ? existing.canonicalName : existing.canonicalName);
          const preferred = categoryPriority[canonicalName];
          // Keep the more specific version
          const betterVersion = tech.version && (!existing.version ||
            tech.version.split('.').length > existing.version.split('.').length)
            ? tech.version : existing.version;

          if (preferred === category) {
            seen.set(normalizedKey, { canonicalName, category, version: betterVersion });
          } else if (!preferred) {
            // No explicit preference - use deterministic category rank as tiebreaker
            const existingRank = categoryRank[existing.category] ?? 99;
            const currentRank = categoryRank[category] ?? 99;
            const winningCategory = currentRank < existingRank ? category : existing.category;
            seen.set(normalizedKey, { canonicalName, category: winningCategory, version: betterVersion });
          } else {
            // Keep existing preferred
            seen.set(normalizedKey, { canonicalName, category: existing.category, version: betterVersion });
          }
        }
      }
    }

    // Second pass: filter to keep only one entry per tech in the chosen category
    const emitted = new Set();
    for (const category of categories) {
      this.detected[category] = this.detected[category].filter(tech => {
        const normalizedKey = this.normalizeTechName(tech.name);
        const chosen = seen.get(normalizedKey);
        if (chosen && chosen.category === category && !emitted.has(normalizedKey)) {
          tech.name = chosen.canonicalName; // Use canonical name
          tech.version = chosen.version; // Update to best version
          emitted.add(normalizedKey);
          return true;
        }
        return false;
      });
    }
  }

  // Check global variables
  checkGlobals(window) {
    const checks = [
      // Frontend Frameworks
      { name: 'React', check: () => window.React || document.querySelector('[data-reactroot], [data-reactid]'), type: 'frameworks', version: () => window.React?.version },
      { name: 'Vue.js', check: () => window.Vue || document.querySelector('[data-v-]'), type: 'frameworks', version: () => window.Vue?.version },
      { name: 'Angular', check: () => window.angular || window.ng || document.querySelector('[ng-version]'), type: 'frameworks', version: () => document.querySelector('[ng-version]')?.getAttribute('ng-version') },
      { name: 'Svelte', check: () => window.__SVELTE__, type: 'frameworks' },
      { name: 'Ember.js', check: () => window.Ember, type: 'frameworks', version: () => window.Ember?.VERSION },
      { name: 'Backbone.js', check: () => window.Backbone, type: 'frameworks', version: () => window.Backbone?.VERSION },
      { name: 'Preact', check: () => window.preact, type: 'frameworks', version: () => window.preact?.version },
      { name: 'Alpine.js', check: () => window.Alpine, type: 'frameworks', version: () => window.Alpine?.version },
      // Modern meta-frameworks
      { name: 'Remix', check: () => window.__remixManifest || window.__remixContext, type: 'frameworks' },
      { name: 'SolidJS', check: () => window._$HY || window.Solid, type: 'frameworks' },
      { name: 'HTMX', check: () => window.htmx, type: 'frameworks', version: () => window.htmx?.version },
      { name: 'Stimulus', check: () => window.Stimulus, type: 'frameworks' },
      { name: 'Turbo', check: () => window.Turbo, type: 'frameworks' },

      // Libraries
      { name: 'jQuery', check: () => window.jQuery || window.$, type: 'libraries', version: () => window.jQuery?.fn?.jquery },
      { name: 'Lodash', check: () => window._, type: 'libraries', version: () => window._?.VERSION },
      { name: 'Underscore.js', check: () => window._ && !window._.VERSION, type: 'libraries' },
      { name: 'Moment.js', check: () => window.moment, type: 'libraries', version: () => window.moment?.version },
      { name: 'Axios', check: () => window.axios, type: 'libraries', version: () => window.axios?.VERSION },
      { name: 'D3.js', check: () => window.d3, type: 'libraries', version: () => window.d3?.version },
      { name: 'Three.js', check: () => window.THREE, type: 'libraries', version: () => window.THREE?.REVISION },
      { name: 'Chart.js', check: () => window.Chart, type: 'libraries', version: () => window.Chart?.version },
      { name: 'Anime.js', check: () => window.anime, type: 'libraries', version: () => window.anime?.version },
      { name: 'GSAP', check: () => window.gsap, type: 'libraries', version: () => window.gsap?.version },

      // Analytics
      { name: 'Google Analytics', check: () => window.ga || window.gtag || window._gaq, type: 'analytics' },
      { name: 'Google Tag Manager', check: () => window.google_tag_manager || window.dataLayer, type: 'analytics' },
      { name: 'Facebook Pixel', check: () => window.fbq || window._fbq, type: 'analytics' },
      { name: 'Hotjar', check: () => window.hj || window._hjSettings, type: 'analytics' },
      { name: 'Mixpanel', check: () => window.mixpanel, type: 'analytics' },
      { name: 'Segment', check: () => window.analytics, type: 'analytics', version: () => window.analytics?.VERSION },

      // Security
      { name: 'reCAPTCHA', check: () => window.grecaptcha, type: 'security' },
      { name: 'hCaptcha', check: () => window.hcaptcha, type: 'security' },
      { name: 'Cloudflare', check: () => window.__CF$cv$params || window._cf_translation, type: 'security' },

      // Web Components & Additional Frameworks
      { name: 'Lit', check: () => window.litElementVersions, type: 'frameworks', version: () => window.litElementVersions?.[window.litElementVersions.length - 1] },
      { name: 'Stencil', check: () => window.__stencil, type: 'frameworks' },
      { name: 'Polymer', check: () => window.Polymer, type: 'frameworks', version: () => window.Polymer?.version },

      // State Management
      { name: 'MobX', check: () => window.mobx, type: 'libraries', version: () => window.mobx?.version },
      { name: 'Redux', check: () => window.__REDUX_DEVTOOLS_EXTENSION__, type: 'libraries' },
      { name: 'Zustand', check: () => window.__zustand, type: 'libraries' },

      // Charting & Visualization
      { name: 'Highcharts', check: () => window.Highcharts, type: 'libraries', version: () => window.Highcharts?.version },
      { name: 'ApexCharts', check: () => window.ApexCharts, type: 'libraries' },
      { name: 'Plotly', check: () => window.Plotly, type: 'libraries', version: () => window.Plotly?.version },

      // Rich Text Editors
      { name: 'TinyMCE', check: () => window.tinymce, type: 'libraries', version: () => window.tinymce?.majorVersion ? `${window.tinymce.majorVersion}.${window.tinymce.minorVersion}` : undefined },
      { name: 'CKEditor', check: () => window.CKEDITOR, type: 'libraries', version: () => window.CKEDITOR?.version },
      { name: 'Quill', check: () => window.Quill, type: 'libraries', version: () => window.Quill?.version },

      // Error Tracking & Observability
      { name: 'Sentry', check: () => window.Sentry || window.__SENTRY__, type: 'analytics' },
      { name: 'LogRocket', check: () => window.LogRocket, type: 'analytics' },
      { name: 'Datadog RUM', check: () => window.DD_RUM, type: 'analytics' },

      // Payment Providers
      { name: 'Stripe', check: () => window.Stripe, type: 'libraries' },
      { name: 'PayPal', check: () => window.paypal, type: 'libraries' },
      { name: 'Braintree', check: () => window.braintree, type: 'libraries' },

      // Backend-as-a-Service
      { name: 'Firebase', check: () => window.firebase, type: 'libraries', version: () => window.firebase?.SDK_VERSION },
      { name: 'Supabase', check: () => window.supabase, type: 'libraries' },
      { name: 'AWS Amplify', check: () => window.aws_amplify, type: 'libraries' },

      // Customer Support & Chat
      { name: 'Intercom', check: () => window.Intercom, type: 'analytics' },
      { name: 'Zendesk', check: () => window.zE, type: 'analytics' },
      { name: 'Drift', check: () => window.drift, type: 'analytics' },

      // Maps
      { name: 'Mapbox', check: () => window.mapboxgl, type: 'libraries', version: () => window.mapboxgl?.version },
      { name: 'Leaflet', check: () => window.L && window.L.map, type: 'libraries', version: () => window.L?.version },
      { name: 'Google Maps', check: () => window.google?.maps, type: 'libraries' },

      // Realtime / WebSockets
      { name: 'Socket.IO', check: () => window.io, type: 'libraries' },
      { name: 'Pusher', check: () => window.Pusher, type: 'libraries' },
      { name: 'Ably', check: () => window.Ably, type: 'libraries' },

      // UI & Animation
      { name: 'Swiper', check: () => window.Swiper, type: 'libraries' },
      { name: 'Lottie', check: () => window.lottie, type: 'libraries' },
      { name: 'Hammer.js', check: () => window.Hammer, type: 'libraries', version: () => window.Hammer?.VERSION },

      // Analytics (additional)
      { name: 'Matomo', check: () => window._paq, type: 'analytics' },
      { name: 'Plausible', check: () => window.plausible, type: 'analytics' },
      { name: 'Amplitude', check: () => window.amplitude, type: 'analytics' },
      { name: 'Clarity', check: () => window.clarity, type: 'analytics' },
      { name: 'FullStory', check: () => window.FS, type: 'analytics' },
      { name: 'Heap', check: () => window.heap, type: 'analytics' },

      // Security (additional)
      { name: 'Turnstile', check: () => window.turnstile, type: 'security' },

      // Build Tools (from webpack bundles)
      { name: 'Webpack', check: () => window.webpackJsonp || window.webpackChunk, type: 'buildTools' },
      { name: 'Vite', check: () => document.querySelector('script[type="module"][src*="@vite"]'), type: 'buildTools' },
      { name: 'Parcel', check: () => window.parcelRequire, type: 'buildTools' }
    ];

    checks.forEach(({ name, check, type, version }) => {
      try {
        if (check()) {
          const tech = { name };
          if (version) {
            const ver = version();
            if (ver) tech.version = ver;
          }
          this.detected[type].push(tech);
        }
      } catch (e) {
        // Check failed, skip
      }
    });
  }

  // Check DOM for framework signatures
  checkDOM(document) {
    // Next.js
    if (document.getElementById('__next')) {
      this.detected.frameworks.push({ name: 'Next.js' });
    }

    // Nuxt.js
    if (document.getElementById('__nuxt')) {
      this.detected.frameworks.push({ name: 'Nuxt.js' });
    }

    // Gatsby
    if (document.getElementById('___gatsby')) {
      this.detected.frameworks.push({ name: 'Gatsby' });
    }

    // SvelteKit
    if (document.querySelector('[data-sveltekit]')) {
      this.detected.frameworks.push({ name: 'SvelteKit' });
    }

    // Astro
    if (document.querySelector('astro-island, astro-slot') ||
        document.querySelector('script[src*="/_astro/"]')) {
      this.detected.frameworks.push({ name: 'Astro' });
    }

    // Qwik
    if (document.querySelector('[q\\:container]') ||
        document.querySelector('script[type="qwik/json"]')) {
      this.detected.frameworks.push({ name: 'Qwik' });
    }

    // Fresh (Deno)
    if (document.querySelector('script[src*="/_frsh/"]')) {
      this.detected.frameworks.push({ name: 'Fresh' });
    }

    // Remix (DOM fallback)
    if (document.querySelector('[data-remix-run]') ||
        document.querySelector('script[src*="/build/"].__remix')) {
      if (!this.detected.frameworks.some(f => f.name === 'Remix')) {
        this.detected.frameworks.push({ name: 'Remix' });
      }
    }

    // HTMX (DOM fallback via attributes)
    if (document.querySelector('[hx-get], [hx-post], [hx-put], [hx-delete], [hx-patch]')) {
      if (!this.detected.frameworks.some(f => f.name === 'HTMX')) {
        this.detected.frameworks.push({ name: 'HTMX' });
      }
    }

    // WordPress
    if (document.querySelector('link[href*="wp-content"]') || 
        document.querySelector('meta[name="generator"][content*="WordPress"]')) {
      const version = document.querySelector('meta[name="generator"]')?.content.match(/WordPress ([\d.]+)/)?.[1];
      this.detected.backend.push({ name: 'WordPress', version });
    }

    // Drupal
    if (document.querySelector('meta[name="Generator"][content*="Drupal"]')) {
      const version = document.querySelector('meta[name="Generator"]')?.content.match(/Drupal ([\d.]+)/)?.[1];
      this.detected.backend.push({ name: 'Drupal', version });
    }

    // Joomla
    if (document.querySelector('meta[name="generator"][content*="Joomla"]')) {
      this.detected.backend.push({ name: 'Joomla' });
    }

    // Shopify
    if (document.querySelector('meta[name="shopify-checkout-api-token"]') ||
        document.querySelector('link[href*="cdn.shopify.com"]')) {
      this.detected.backend.push({ name: 'Shopify' });
    }

    // Wix
    if (document.querySelector('meta[name="generator"][content*="Wix"]')) {
      this.detected.backend.push({ name: 'Wix' });
    }

    // Squarespace
    if (document.querySelector('link[href*="squarespace.com"]')) {
      this.detected.backend.push({ name: 'Squarespace' });
    }

    // UI Framework detection

    // Tailwind CSS: sample elements for utility class patterns
    try {
      const tailwindClasses = /\b(?:flex|p-\d|mt-\d|mb-\d|mx-\d|my-\d|pt-\d|pb-\d|px-\d|py-\d|bg-|text-(?:sm|lg|xl|xs|base|center|left|right)|rounded|shadow|grid|block|inline|hidden|w-\d|h-\d)\b/;
      const sampleElements = document.querySelectorAll('body *');
      let tailwindCount = 0;
      const sampleLimit = Math.min(sampleElements.length, 200);
      for (let i = 0; i < sampleLimit; i++) {
        const cls = sampleElements[i].className;
        if (typeof cls === 'string' && tailwindClasses.test(cls)) {
          tailwindCount++;
          if (tailwindCount >= 5) break;
        }
      }
      if (tailwindCount >= 5) {
        this.detected.libraries.push({ name: 'Tailwind CSS' });
      }
    } catch (e) {
      // DOM access failed
    }

    // Bootstrap
    if (document.querySelector('.container .row [class*="col-"]') ||
        (document.querySelector('.container') && document.querySelector('.row') && document.querySelector('[class*="col-"]'))) {
      this.detected.libraries.push({ name: 'Bootstrap' });
    }

    // Material UI
    if (document.querySelector('[class*="MuiButton"], [class*="MuiPaper"], [class*="MuiTypography"], [class*="Mui"]')) {
      this.detected.libraries.push({ name: 'Material UI' });
    }

    // Chakra UI
    if (document.querySelector('[class*="chakra-"]')) {
      this.detected.libraries.push({ name: 'Chakra UI' });
    }

    // Ant Design
    if (document.querySelector('[class*="ant-"]')) {
      this.detected.libraries.push({ name: 'Ant Design' });
    }

    // Semantic UI
    if (document.querySelector('.ui.segment, .ui.container, .ui.grid, .ui.menu, .ui.form')) {
      this.detected.libraries.push({ name: 'Semantic UI' });
    }

    // Eleventy
    if (document.querySelector('meta[name="generator"][content*="Eleventy"]')) {
      this.detected.frameworks.push({ name: 'Eleventy' });
    }

    // Webflow
    if (document.querySelector('html.wf-page, html[data-wf-page], [data-wf-page]')) {
      this.detected.backend.push({ name: 'Webflow' });
    }

    // Framer
    if (document.querySelector('meta[name="generator"][content*="Framer"]')) {
      this.detected.backend.push({ name: 'Framer' });
    }

    // Ghost (DOM fallback - also detected via meta in checkMetaTags)
    if (document.querySelector('meta[name="generator"][content*="Ghost"]')) {
      if (!this.detected.backend.some(b => b.name === 'Ghost')) {
        const version = document.querySelector('meta[name="generator"]')?.content.match(/Ghost ([\d.]+)/)?.[1];
        this.detected.backend.push({ name: 'Ghost', version });
      }
    }

    // Magento
    if (document.querySelector('script[src*="mage/"]') ||
        document.querySelector('body[class*="cms-"]') ||
        document.querySelector('script[src*="Magento_"]')) {
      this.detected.backend.push({ name: 'Magento' });
    }

    // PrestaShop
    if (document.querySelector('meta[name="generator"][content*="PrestaShop"]')) {
      const version = document.querySelector('meta[name="generator"]')?.content.match(/PrestaShop ([\d.]+)/)?.[1];
      this.detected.backend.push({ name: 'PrestaShop', version });
    }

    // Bubble
    if (document.querySelector('script[src*="bubble.io"]')) {
      this.detected.backend.push({ name: 'Bubble' });
    }
  }

  // Check HTTP headers (uses shared headers from analyzer-coordinator when available)
  async checkHeaders() {
    try {
      let headers;

      // Use shared headers from analyzer-coordinator to avoid redundant fetch
      if (window._origamiHeaders) {
        headers = window._origamiHeaders;
      } else {
        const response = await fetch(window.location.href, { method: 'HEAD' });
        headers = {};
        response.headers.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });
      }

      const getHeader = (name) => headers[name.toLowerCase()] || null;

      // Server header
      const server = getHeader('server');
      if (server) {
        const serverMatch = this.parseServerHeader(server);
        if (serverMatch) {
          this.detected.backend.push(serverMatch);
        }
      }

      // X-Powered-By
      const xPoweredBy = getHeader('x-powered-by');
      if (xPoweredBy) {
        const poweredBy = this.parseXPoweredBy(xPoweredBy);
        if (poweredBy) {
          this.detected.backend.push(poweredBy);
        }
      }

      // CDN detection from headers
      if (getHeader('cf-ray') && !this.detected.cdn.some(c => c.name === 'Cloudflare')) {
        this.detected.cdn.push({ name: 'Cloudflare' });
      }

      const xCacheHeader = getHeader('x-cache');
      if (xCacheHeader && xCacheHeader.includes('cloudfront')) {
        this.detected.cdn.push({ name: 'AWS CloudFront' });
      }

      if (getHeader('x-akamai-transformed')) {
        this.detected.cdn.push({ name: 'Akamai' });
      }

      const fastly = getHeader('x-served-by');
      if (fastly && fastly.includes('fastly')) {
        this.detected.cdn.push({ name: 'Fastly' });
      }

      // Hosting/platform detection from headers
      this.detectHosting(getHeader);

      // WAF detection from headers
      this.detectWAF(getHeader);

    } catch (error) {
      // Can't check headers
    }
  }

  // Detect Web Application Firewalls from response headers
  detectWAF(getHeader) {
    const wafSignatures = [
      // Cloudflare WAF (distinct from CDN - look for challenge/firewall indicators)
      { header: 'cf-mitigated', name: 'Cloudflare WAF' },
      { header: 'cf-chl-bypass', name: 'Cloudflare WAF' },
      // Sucuri
      { header: 'x-sucuri-id', name: 'Sucuri WAF' },
      { header: 'x-sucuri-cache', name: 'Sucuri WAF' },
      // Imperva / Incapsula
      { header: 'x-iinfo', name: 'Imperva/Incapsula WAF' },
      { header: 'x-cdn', name: 'Imperva/Incapsula WAF', match: /incapsula/i },
      // ModSecurity
      { header: 'x-denied-reason', name: 'ModSecurity WAF' },
      // F5 BIG-IP ASM
      { header: 'x-wa-info', name: 'F5 BIG-IP ASM' },
      // AWS WAF
      { header: 'x-amzn-waf-action', name: 'AWS WAF' },
      // Barracuda
      { header: 'barra_counter_session', name: 'Barracuda WAF' },
      // DenyAll / Rohde & Schwarz
      { header: 'x-denied-reason', name: 'DenyAll WAF' },
      // Wordfence (WordPress)
      { header: 'x-wordfence-blocked', name: 'Wordfence WAF' },
    ];

    for (const { header, name, match } of wafSignatures) {
      const value = getHeader(header);
      if (value) {
        if (match && !match.test(value)) continue;
        if (!this.detected.security.some(s => s.name === name)) {
          this.detected.security.push({ name });
        }
      }
    }

    // Check Server header for WAF signatures
    const server = getHeader('server');
    if (server) {
      const serverWAFs = [
        { regex: /\bBIG-IP\b/i, name: 'F5 BIG-IP' },
        { regex: /\bBarracuda\b/i, name: 'Barracuda WAF' },
        { regex: /\bSucuri/i, name: 'Sucuri WAF' },
      ];
      for (const { regex, name } of serverWAFs) {
        if (regex.test(server) && !this.detected.security.some(s => s.name === name)) {
          this.detected.security.push({ name });
        }
      }
    }
  }

  // Detect hosting platforms from response headers
  detectHosting(getHeader) {
    const hostingSignatures = [
      { header: 'x-vercel-id', name: 'Vercel' },
      { header: 'x-nf-request-id', name: 'Netlify' },
      { header: 'x-amz-cf-id', name: 'AWS CloudFront' },
      { header: 'x-render-origin-server', name: 'Render' },
      { header: 'x-railway', name: 'Railway' },
      { header: 'fly-request-id', name: 'Fly.io' },
    ];

    for (const { header, name } of hostingSignatures) {
      const value = getHeader(header);
      if (value && !this.detected.hosting.some(h => h.name === name)) {
        this.detected.hosting.push({ name });
      }
    }

    // Heroku: via header containing 'vegur'
    const via = getHeader('via');
    if (via && /vegur/i.test(via) && !this.detected.hosting.some(h => h.name === 'Heroku')) {
      this.detected.hosting.push({ name: 'Heroku' });
    }
  }

  // Parse Server header
  parseServerHeader(server) {
    const patterns = [
      { regex: /nginx(?:\/([0-9.]+))?/i, name: 'Nginx' },
      { regex: /Apache(?:\/([0-9.]+))?/i, name: 'Apache' },
      { regex: /Microsoft-IIS(?:\/([0-9.]+))?/i, name: 'IIS' },
      { regex: /cloudflare/i, name: 'Cloudflare', cdn: true },
      { regex: /AmazonS3/i, name: 'Amazon S3' },
      { regex: /LiteSpeed/i, name: 'LiteSpeed' },
      { regex: /Caddy/i, name: 'Caddy' }
    ];

    for (const { regex, name, cdn } of patterns) {
      const match = server.match(regex);
      if (match) {
        const tech = { name };
        if (match[1]) tech.version = match[1];
        if (cdn && !this.detected.cdn.some(c => c.name === tech.name)) this.detected.cdn.push(tech);
        return tech;
      }
    }

    return null;
  }

  // Parse X-Powered-By header
  parseXPoweredBy(xPoweredBy) {
    const patterns = [
      { regex: /PHP(?:\/([0-9.]+))?/i, name: 'PHP' },
      { regex: /ASP\.NET/i, name: 'ASP.NET' },
      { regex: /Express/i, name: 'Express.js' },
      { regex: /Django/i, name: 'Django' },
      { regex: /Flask/i, name: 'Flask' },
      { regex: /Ruby/i, name: 'Ruby' },
      { regex: /Next\.js/i, name: 'Next.js' }
    ];

    for (const { regex, name } of patterns) {
      const match = xPoweredBy.match(regex);
      if (match) {
        const tech = { name };
        if (match[1]) tech.version = match[1];
        return tech;
      }
    }

    return null;
  }

  // Check scripts for CDN patterns
  checkScripts(document) {
    const scripts = document.querySelectorAll('script[src]');
    const cdnPatterns = [
      { regex: /cdn\.jsdelivr\.net/, name: 'jsDelivr' },
      { regex: /unpkg\.com/, name: 'unpkg' },
      { regex: /cdnjs\.cloudflare\.com/, name: 'cdnjs' },
      { regex: /ajax\.googleapis\.com/, name: 'Google CDN' },
      { regex: /maxcdn\.bootstrapcdn\.com/, name: 'BootstrapCDN' }
    ];

    // Technology-specific script patterns (detect tech from script src)
    const techScriptPatterns = [
      { regex: /sentry\.io|browser\.sentry-cdn\.com/, name: 'Sentry', type: 'analytics' },
      { regex: /js\.stripe\.com/, name: 'Stripe', type: 'libraries' },
      { regex: /maps\.googleapis\.com/, name: 'Google Maps', type: 'libraries' },
      { regex: /recaptcha\/api\.js/, name: 'reCAPTCHA', type: 'security' },
      { regex: /hcaptcha\.com/, name: 'hCaptcha', type: 'security' },
      { regex: /challenges\.cloudflare\.com\/turnstile/, name: 'Turnstile', type: 'security' }
    ];

    scripts.forEach(script => {
      const src = script.src;

      cdnPatterns.forEach(({ regex, name }) => {
        if (regex.test(src) && !this.detected.cdn.some(c => c.name === name)) {
          this.detected.cdn.push({ name });
        }
      });

      // Check for technology-specific script patterns
      techScriptPatterns.forEach(({ regex, name, type }) => {
        if (regex.test(src) && !this.detected[type].some(t => t.name === name)) {
          this.detected[type].push({ name });
        }
      });

      // Check for specific library versions in CDN URLs
      this.extractVersionFromURL(src);
    });
  }

  // Extract version from CDN URL (Enhanced for better CVE detection)
  extractVersionFromURL(url) {
    const patterns = [
      // Frontend Frameworks
      { regex: /react(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'React', type: 'frameworks' },
      { regex: /vue(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Vue.js', type: 'frameworks' },
      { regex: /angular(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Angular', type: 'frameworks' },
      { regex: /ember(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Ember.js', type: 'frameworks' },
      { regex: /backbone(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Backbone.js', type: 'frameworks' },
      { regex: /svelte(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Svelte', type: 'frameworks' },

      // Libraries - Enhanced patterns with more variations
      { regex: /jquery(?:@|\/|-|\.min\.|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'jQuery', type: 'libraries' },
      { regex: /lodash(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Lodash', type: 'libraries' },
      { regex: /underscore(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Underscore.js', type: 'libraries' },
      { regex: /moment(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Moment.js', type: 'libraries' },
      { regex: /axios(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Axios', type: 'libraries' },
      { regex: /d3(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'D3.js', type: 'libraries' },
      { regex: /three(?:@|\/|-)(?:r)?([0-9]+)/i, name: 'Three.js', type: 'libraries' },
      { regex: /chart\.js(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Chart.js', type: 'libraries' },
      { regex: /bootstrap(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Bootstrap', type: 'libraries' },
      { regex: /gsap(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'GSAP', type: 'libraries' },

      // Additional libraries commonly affected by CVEs
      { regex: /handlebars(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Handlebars.js', type: 'libraries' },
      { regex: /mustache(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Mustache.js', type: 'libraries' },
      { regex: /marked(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Marked', type: 'libraries' },
      { regex: /dompurify(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'DOMPurify', type: 'libraries' },
      { regex: /socket\.io(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Socket.IO', type: 'libraries' },

      // UI Frameworks
      { regex: /next(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Next.js', type: 'frameworks' },
      { regex: /nuxt(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Nuxt.js', type: 'frameworks' },
      { regex: /gatsby(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Gatsby', type: 'frameworks' },

      // Charting & Visualization
      { regex: /highcharts(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Highcharts', type: 'libraries' },
      { regex: /apexcharts(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'ApexCharts', type: 'libraries' },
      { regex: /plotly(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Plotly', type: 'libraries' },

      // Rich Text Editors
      { regex: /tinymce(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'TinyMCE', type: 'libraries' },
      { regex: /ckeditor(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'CKEditor', type: 'libraries' },
      { regex: /quill(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Quill', type: 'libraries' },

      // Maps
      { regex: /mapbox-gl(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Mapbox', type: 'libraries' },
      { regex: /leaflet(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Leaflet', type: 'libraries' },

      // Realtime
      { regex: /pusher(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Pusher', type: 'libraries' },

      // UI & Animation
      { regex: /swiper(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Swiper', type: 'libraries' },
      { regex: /lottie(?:-web)?(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Lottie', type: 'libraries' },
      { regex: /hammer(?:\.js)?(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Hammer.js', type: 'libraries' },

      // Payment
      { regex: /braintree(?:-web)?(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Braintree', type: 'libraries' },

      // BaaS
      { regex: /firebase(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Firebase', type: 'libraries' },

      // Web Components
      { regex: /lit(?:-element|-html)?(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Lit', type: 'frameworks' },

      // State Management
      { regex: /mobx(?:@|\/|-)([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'MobX', type: 'libraries' }
    ];

    patterns.forEach(({ regex, name, type }) => {
      const match = url.match(regex);
      if (match) {
        const version = match[1];

        // Normalize version (remove leading zeros, ensure proper format)
        const normalizedVersion = this.normalizeVersion(version);

        const existing = this.detected[type].find(t => t.name === name);
        if (existing) {
          // Update version if not present or if new version is more specific
          if (!existing.version || (normalizedVersion && normalizedVersion.split('.').length > (existing.version.split('.').length))) {
            existing.version = normalizedVersion;
          }
        } else {
          this.detected[type].push({ name, version: normalizedVersion });
        }
      }
    });
  }

  // Normalize version string for consistent format
  normalizeVersion(version) {
    if (!version) return null;

    // Remove leading 'v' if present
    version = version.replace(/^v/i, '');

    // Ensure we have at least major.minor.patch format
    const parts = version.split('.');
    while (parts.length < 3) {
      parts.push('0');
    }

    // Take only first 3 parts (major.minor.patch)
    return parts.slice(0, 3).join('.');
  }

  // Check meta tags
  checkMetaTags(document) {
    // Generator meta tag
    const generator = document.querySelector('meta[name="generator"]');
    if (generator) {
      const content = generator.content;
      
      // Already checked WordPress, Drupal, etc. in checkDOM
      // Check for others
      if (content.includes('Hugo')) {
        this.detected.backend.push({ name: 'Hugo' });
      } else if (content.includes('Jekyll')) {
        this.detected.backend.push({ name: 'Jekyll' });
      } else if (content.includes('Ghost')) {
        this.detected.backend.push({ name: 'Ghost' });
      }
    }

    // Framework-specific meta tags
    if (document.querySelector('meta[name="next-head-count"]')) {
      if (!this.detected.frameworks.some(f => f.name === 'Next.js')) {
        this.detected.frameworks.push({ name: 'Next.js' });
      }
    }
  }

  // Check cookies for technology indicators
  checkCookies() {
    const cookies = document.cookie.split(';').map(c => c.trim());
    
    cookies.forEach(cookie => {
      const [name] = cookie.split('=');
      
      if (name.includes('PHPSESSID')) {
        if (!this.detected.backend.some(b => b.name === 'PHP')) {
          this.detected.backend.push({ name: 'PHP' });
        }
      } else if (name.includes('JSESSIONID')) {
        if (!this.detected.backend.some(b => b.name === 'Java')) {
          this.detected.backend.push({ name: 'Java/JSP' });
        }
      } else if (name.includes('ASP.NET_SessionId')) {
        if (!this.detected.backend.some(b => b.name === 'ASP.NET')) {
          this.detected.backend.push({ name: 'ASP.NET' });
        }
      } else if (name.includes('laravel_session')) {
        if (!this.detected.backend.some(b => b.name === 'Laravel')) {
          this.detected.backend.push({ name: 'Laravel' });
        }
      }
    });
  }

  // Analyze build patterns
  analyzeBuildPatterns(document) {
    const scripts = document.querySelectorAll('script[src]');
    
    scripts.forEach(script => {
      const src = script.src;
      
      // Webpack
      if (src.includes('webpack') || src.match(/\.[a-f0-9]{8,}\.js$/)) {
        if (!this.detected.buildTools.some(b => b.name === 'Webpack')) {
          this.detected.buildTools.push({ name: 'Webpack' });
        }
      }
      
      // Vite
      if (src.includes('@vite') || src.includes('/.vite/')) {
        if (!this.detected.buildTools.some(b => b.name === 'Vite')) {
          this.detected.buildTools.push({ name: 'Vite' });
        }
      }
      
      // Rollup
      if (src.includes('rollup')) {
        if (!this.detected.buildTools.some(b => b.name === 'Rollup')) {
          this.detected.buildTools.push({ name: 'Rollup' });
        }
      }
    });
  }

  // Get summary
  getSummary() {
    const total = Object.values(this.detected).reduce((sum, arr) => sum + arr.length, 0);
    
    return {
      total,
      frameworks: this.detected.frameworks.length,
      libraries: this.detected.libraries.length,
      backend: this.detected.backend.length,
      cdn: this.detected.cdn.length,
      analytics: this.detected.analytics.length,
      security: this.detected.security.length,
      buildTools: this.detected.buildTools.length,
      hosting: this.detected.hosting.length
    };
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = TechnologyFingerprinter;
}

