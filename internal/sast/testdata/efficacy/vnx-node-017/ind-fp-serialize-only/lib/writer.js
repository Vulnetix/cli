const serialize = require('node-serialize');

function dump(obj) {
  return serialize.serialize(obj);
}
module.exports = dump;
