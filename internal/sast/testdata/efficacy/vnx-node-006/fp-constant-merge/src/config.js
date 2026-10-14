const _ = require('lodash');
const base = require('./base.json');
const overrides = require('./production.json');

module.exports = _.merge({}, base, overrides);
