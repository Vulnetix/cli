const path = require('path');
const registry = require('./registry');

module.exports = {
  root: path.resolve(__dirname, '..'),
  plugins: registry.list(),
};
