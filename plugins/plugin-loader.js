// Origami Plugin Loader
// Loads enabled plugins from chrome.storage.local and registers them with the coordinator

(function() {
  'use strict';

  const STORAGE_KEY = 'origami_plugins';

  // Initialize the global plugin registry
  if (typeof window.PluginRegistry !== 'undefined') {
    window._origamiPluginRegistry = new PluginRegistry();
  } else {
    console.error('Origami: PluginRegistry not loaded, plugin system unavailable');
    return;
  }

  function loadPlugins() {
    chrome.storage.local.get([STORAGE_KEY], (data) => {
      const plugins = data[STORAGE_KEY] || [];
      let loadedCount = 0;

      plugins.forEach(pluginData => {
        if (!pluginData.enabled) return;

        try {
          // Register the plugin manifest
          const result = window._origamiPluginRegistry.register(pluginData);
          if (!result.success) {
            console.error('Origami: Failed to register plugin:', pluginData.manifest?.id, result.errors);
            return;
          }

          // If plugin has code, inject it into the page context
          if (pluginData.code) {
            injectPluginCode(pluginData);
          }

          loadedCount++;
        } catch (e) {
          console.error('Origami: Error loading plugin:', pluginData.manifest?.id, e);
        }
      });

      if (loadedCount > 0) {
        console.log('Origami: Loaded', loadedCount, 'plugin(s)');
      }

      // Signal that plugins are loaded and ready
      document.dispatchEvent(new CustomEvent('origami-plugins-ready', {
        detail: { count: loadedCount }
      }));
    });
  }

  function injectPluginCode(pluginData) {
    const manifest = pluginData.manifest;

    try {
      // Wrap plugin code in a safety boundary with dangerous globals shadowed
      const wrappedCode = `
(function(fetch, XMLHttpRequest, WebSocket, eval, Function, importScripts, chrome, globalThis, self) {
  'use strict';
  try {
    ${pluginData.code}

    // After code execution, dispatch registration event
    if (typeof ${manifest.analyzerClass} !== 'undefined') {
      document.dispatchEvent(new CustomEvent('origami-plugin-register', {
        detail: {
          id: ${JSON.stringify(manifest.id)},
          name: ${JSON.stringify(manifest.name)},
          analyzerClass: ${JSON.stringify(manifest.analyzerClass)},
          resultCategory: ${JSON.stringify(manifest.resultCategory)}
        }
      }));
    } else {
      console.error('Origami: Plugin ' + ${JSON.stringify(manifest.id)} + ' did not define class ' + ${JSON.stringify(manifest.analyzerClass)});
    }
  } catch (e) {
    console.error('Origami: Plugin ' + ${JSON.stringify(manifest.id)} + ' execution error:', e);
  }
})();`;

      // Execute the wrapped code in the content script's isolated world
      try {
        const fn = new Function(wrappedCode);
        fn();
      } catch (execErr) {
        console.error('Origami: Plugin execution error:', execErr);
      }
    } catch (e) {
      console.error('Origami: Failed to inject plugin code for:', manifest.id, e);
    }
  }

  // Listen for storage changes to handle live plugin enable/disable
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes[STORAGE_KEY]) {
      console.log('Origami: Plugin storage changed, reloading plugins');
      window._origamiPluginRegistry.clear();
      loadPlugins();
    }
  });

  // Load plugins once DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadPlugins);
  } else {
    loadPlugins();
  }

  console.log('Origami: Plugin loader initialized');
})();
