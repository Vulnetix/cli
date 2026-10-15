class ConfigStore {
  constructor(defaults) {
    this.values = {};
    this.merge(this.values, defaults);
  }

  merge(target, source) {
    for (const key in source) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
~>        this.merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
}

module.exports = ConfigStore;
