'use strict';

exports.find = function find(req, res) {
  const term = req.query.search;
~>  const re = new RegExp(term, 'gi');
  res.json(users.filter((u) => re.test(u.name)));
};

exports.prefix = function prefix(req, res) {
  const { prefix } = req.params;
~>  const matcher = new RegExp(
    '^' + prefix,
  );
  res.json(paths.filter((p) => matcher.test(p)));
};

exports.locate = function locate(req, res) {
  const needle = req.body.needle;
~>  res.json({ at: description.match(needle) });
};
