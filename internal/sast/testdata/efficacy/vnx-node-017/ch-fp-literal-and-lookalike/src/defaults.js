const serialize = require('node-serialize');

// serialize.unserialize(req.cookies.profile) is unsafe, never do that.
const DEFAULTS = serialize.unserialize('{"theme":"dark","lang":"en"}');
const help = "call serialize.unserialize(input) only on trusted data";

function myunserialize(s) {
  return JSON.parse(s);
}

module.exports = { DEFAULTS, help, value: myunserialize('{}') };
