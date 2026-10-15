const UNSAFE = new Set(['__proto__', 'constructor', 'prototype']);

function deepMerge(target, source) {
  for (const key in source) {
    if (UNSAFE.has(key)) continue;
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function merge2(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor') {
      continue;
    }
    target[key] = typeof source[key] === 'object' ? merge2(target[key] || {}, source[key]) : source[key];
  }
  return target;
}

module.exports = { deepMerge, merge2 };
