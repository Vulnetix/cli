const path = require('path');

function safeKey(key) {
~>  return key.replace(/\.\.[\/\\]/, '');
}

function windowsSafe(name) {
~>  return name.replace("..\\", "");
}

module.exports = { safeKey, windowsSafe };
