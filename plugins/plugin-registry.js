// Origami Plugin Registry
// Tracks registered plugins, provides query/enable/disable API

class PluginRegistry {
  constructor() {
    this._plugins = new Map();
    this._validator = new PluginValidator();
  }

  register(pluginData) {
    const validation = this._validator.validatePlugin(pluginData);
    if (!validation.valid) {
      console.error('Origami: Plugin registration failed:', validation.errors);
      return { success: false, errors: validation.errors };
    }

    const rawManifest = pluginData.manifest || pluginData;
    // Sanitize manifest: only copy known-safe properties to prevent prototype pollution
    const manifest = {
      id: rawManifest.id,
      name: rawManifest.name,
      version: rawManifest.version,
      analyzerClass: rawManifest.analyzerClass,
      resultCategory: rawManifest.resultCategory,
      description: rawManifest.description || '',
      author: rawManifest.author || '',
      enabled: rawManifest.enabled
    };
    const id = manifest.id;

    if (this._plugins.has(id)) {
      console.warn('Origami: Plugin already registered, updating:', id);
    }

    this._plugins.set(id, {
      manifest: manifest,
      code: pluginData.code || null,
      enabled: manifest.enabled !== false,
      registeredAt: new Date().toISOString()
    });

    console.log('Origami: Plugin registered:', id, manifest.name);
    return { success: true, id: id };
  }

  unregister(pluginId) {
    if (!this._plugins.has(pluginId)) {
      return { success: false, error: 'Plugin not found: ' + pluginId };
    }
    this._plugins.delete(pluginId);
    console.log('Origami: Plugin unregistered:', pluginId);
    return { success: true };
  }

  get(pluginId) {
    return this._plugins.get(pluginId) || null;
  }

  getAll() {
    return Array.from(this._plugins.values());
  }

  getEnabled() {
    return this.getAll().filter(p => p.enabled);
  }

  enable(pluginId) {
    const plugin = this._plugins.get(pluginId);
    if (!plugin) return { success: false, error: 'Plugin not found' };
    plugin.enabled = true;
    return { success: true };
  }

  disable(pluginId) {
    const plugin = this._plugins.get(pluginId);
    if (!plugin) return { success: false, error: 'Plugin not found' };
    plugin.enabled = false;
    return { success: true };
  }

  toggle(pluginId) {
    const plugin = this._plugins.get(pluginId);
    if (!plugin) return { success: false, error: 'Plugin not found' };
    plugin.enabled = !plugin.enabled;
    return { success: true, enabled: plugin.enabled };
  }

  has(pluginId) {
    return this._plugins.has(pluginId);
  }

  count() {
    return this._plugins.size;
  }

  clear() {
    this._plugins.clear();
  }

  query(filter = {}) {
    let results = this.getAll();

    if (filter.enabled !== undefined) {
      results = results.filter(p => p.enabled === filter.enabled);
    }

    if (filter.category) {
      results = results.filter(p => p.manifest.resultCategory === filter.category);
    }

    if (filter.search) {
      const term = filter.search.toLowerCase();
      results = results.filter(p =>
        p.manifest.name.toLowerCase().includes(term) ||
        p.manifest.id.toLowerCase().includes(term) ||
        (p.manifest.description || '').toLowerCase().includes(term)
      );
    }

    return results;
  }
}

// Make available globally for content scripts
if (typeof window !== 'undefined') {
  window.PluginRegistry = PluginRegistry;
}
