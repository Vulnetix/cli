const _ = require('lodash');
const escapeStringRegexp = require('escape-string-regexp');
const RE2 = require('re2');

exports.s = (req, res) => {
  const a = new RegExp(_.escapeRegExp(req.query.q), 'i');
  const b = new RegExp(escapeStringRegexp(req.body.term));
  const c = new RE2(req.query.pattern);
  const d = new RegExp(req.query.x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  res.json({ a: a.source, b: b.source, c: c.source, d: d.source });
};
