const { deserialize } = require('serialize-to-js');

function hydrate(payload) {
~>  return deserialize(
    payload.data
  );
}
module.exports = { hydrate };
