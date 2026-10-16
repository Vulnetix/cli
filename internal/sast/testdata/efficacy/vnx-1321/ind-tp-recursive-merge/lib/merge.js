function isObject(v) {
  return v !== null && typeof v === 'object';
}

function deepMerge(target, source) {
  for (const key in source) {
    if (isObject(source[key])) {
      if (!target[key]) target[key] = {};
~>      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
module.exports = deepMerge;
