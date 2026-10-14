const escapeRegExp = require('lodash/escapeRegExp');
const RE2 = require('re2');

function find(req, res) {
  const re = new RegExp(escapeRegExp(req.query.q), 'i');
  res.json(items.filter((i) => re.test(i)));
}

function exact(req, res) {
  const safe = req.query.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp('^' + safe + '$');
  res.json(items.filter((i) => re.test(i)));
}

function linear(req, res) {
  const re = new RE2(req.query.pattern);
  res.json(items.filter((i) => re.test(i)));
}

module.exports = { find, exact, linear };
