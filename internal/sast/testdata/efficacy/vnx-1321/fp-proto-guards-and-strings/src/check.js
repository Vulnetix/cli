// Reject keys such as obj[key] where key is "__proto__" to stop prototype pollution.
function isSafeKey(key) {
  return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';
}

const message = "do not write target[key] = source[key] in a recursive merge";

function readProto(obj) {
  return Object.getPrototypeOf(obj) === Object.prototype || obj.__proto__ === null;
}

module.exports = { isSafeKey, message, readProto };
