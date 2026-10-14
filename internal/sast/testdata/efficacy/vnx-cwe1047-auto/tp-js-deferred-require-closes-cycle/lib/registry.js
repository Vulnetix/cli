const plugins = [];

function list() {
  return plugins.slice();
}

function rootDir() {
~>  const config = require('./config');
  return config.root;
}

module.exports = { list, rootDir };
