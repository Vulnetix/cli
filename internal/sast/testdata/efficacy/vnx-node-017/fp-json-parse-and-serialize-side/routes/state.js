const serialize = require('node-serialize');

// Saving only: serialize() produces the payload, it never evaluates one.
function save(res, state) {
  res.cookie('state', Buffer.from(serialize.serialize(state)).toString('base64'));
}

function load(req) {
  const parsed = JSON.parse(req.body.state);
  return parsed;
}

// A constant payload written by the program itself.
const defaults = serialize.unserialize('{"theme":"dark","lang":"en"}');

module.exports = { save, load, defaults };
