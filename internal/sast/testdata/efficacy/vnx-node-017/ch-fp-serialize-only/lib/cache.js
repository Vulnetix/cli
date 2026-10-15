const serialize = require('node-serialize');

function store(cache, key, value) {
  cache.set(key, serialize.serialize(value));
}

function load(cache, key) {
  return JSON.parse(cache.get(key));
}

module.exports = { store, load };
