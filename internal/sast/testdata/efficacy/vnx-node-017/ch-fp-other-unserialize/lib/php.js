const { unserialize } = require('php-serialize');
const phpUnserialize = require('locutus/php/var/unserialize');

function readWordpressOption(row) {
  const viaLib = unserialize(row.option_value);
  const viaLocutus = phpUnserialize(row.option_value);
  return viaLib || viaLocutus;
}

class Store {
  unserialize(text) {
    return JSON.parse(text);
  }
}

module.exports = { readWordpressOption, Store };
