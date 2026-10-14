const VERSION = 'v2';
const config = require('./config');

const apiRe = new RegExp('^/api/' + VERSION + '/');
const custom = new RegExp(config.allowedPattern);

function check(req, res) {
  const digits = req.query.id.match(/^\d+$/);
  const found = req.body.text.search(/error/i);
  res.json({ digits, found, api: apiRe.test(req.path), custom: custom.test(req.path) });
}

module.exports = { check };
