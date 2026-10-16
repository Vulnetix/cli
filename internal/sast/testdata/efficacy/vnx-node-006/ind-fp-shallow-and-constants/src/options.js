const _ = require('lodash');
const fileConfig = require('./config.json');

function build(req) {
  const a = Object.assign({}, req.body);
  const b = { ...req.body, source: 'api' };
  const c = _.merge({}, DEFAULTS, fileConfig);
  const d = _.merge(DEFAULTS, _.pick(req.body, ['theme', 'locale']));
  const e = _.get(req.body, 'user.name');
  return { a, b, c, d, e };
}

const DEFAULTS = { theme: 'light', locale: 'en' };
module.exports = { build };
