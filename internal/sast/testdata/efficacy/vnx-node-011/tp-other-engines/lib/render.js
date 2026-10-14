const _ = require('lodash');
const doT = require('dot');
const Mustache = require('mustache');

function lodashPreview(req, res) {
~>  const compiled = _.template(req.body.tpl);
  res.send(compiled({ user: req.user }));
}

function dotPreview(req, res) {
~>  const fn = doT.template(req.body.tpl);
  res.send(fn({}));
}

function mustachePreview(req, res) {
~>  res.send(Mustache.render(req.query.view, { name: 'x' }));
}

module.exports = { lodashPreview, dotPreview, mustachePreview };
