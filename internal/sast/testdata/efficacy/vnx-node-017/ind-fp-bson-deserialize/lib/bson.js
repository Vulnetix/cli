const { deserialize } = require('bson');
const avro = require('avsc');

function read(buf) {
  const doc = deserialize(buf);
  return doc;
}
module.exports = { read };
