const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);

function isPlain(v) {
  return Object.prototype.toString.call(v) === '[object Object]';
}

function noop() {}
function noop2() {}
function noop3() {}
function noop4() {}
function noop5() {}

function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (RESERVED.has(key)) continue;
    if (isPlain(source[key])) {
      target[key] = target[key] || {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = merge;
