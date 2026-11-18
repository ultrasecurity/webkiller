class ModuleResult {
  constructor(opts = {}) {
    this.module = opts.module || '';
    this.status = opts.status || 'success';
    this.items = opts.items || [];
    this.records = opts.records || [];
    this.errors = opts.errors || [];
    this.duration = opts.duration || 0;
    this.toolUsed = opts.toolUsed || '';
    this.fallback = opts.fallback || false;
  }
}

class BaseModule {
  static moduleName = 'base';
  static phase = 'unknown';
  static toolsNeeded = [];

  constructor(workspace, scope, config, eventCallback) {
    this.workspace = workspace;
    this.scope = scope;
    this.config = config;
    this.emit = eventCallback || (() => {});
  }

  async run() {
    const start = Date.now();
    this.emit('module_start', { module: this.constructor.moduleName, phase: this.constructor.phase });
    try {
      const result = await this.execute();
      result.duration = (Date.now() - start) / 1000;
      this.emit('module_done', { module: this.constructor.moduleName, items: result.items.length, duration: result.duration });
      return result;
    } catch (err) {
      this.emit('module_error', { module: this.constructor.moduleName, error: err.message });
      return new ModuleResult({
        module: this.constructor.moduleName,
        status: 'error',
        errors: [err.message],
        duration: (Date.now() - start) / 1000,
      });
    }
  }

  async execute() {
    throw new Error('not implemented');
  }
}

module.exports = { ModuleResult, BaseModule };
