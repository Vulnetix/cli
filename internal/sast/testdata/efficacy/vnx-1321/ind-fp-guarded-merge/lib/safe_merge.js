const UNSAFE = new Set(['__proto__', 'constructor', 'prototype']);

function deepMerge(target, source) {
  for (const key in source) {
    if (UNSAFE.has(key)) continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
module.exports = deepMerge;
