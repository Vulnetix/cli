'use strict';
const pug = require('pug');
const nunjucks = require('nunjucks');
const ejs = require('ejs');

exports.render = function render(req, res) {
  const source = req.body.source;
~>  const fn = pug.compile(source, { pretty: true });
  res.send(fn({ name: 'Ada' }));
};

exports.greet = function greet(req, res) {
  const name = req.query.name;
  const tpl = 'Hello ' + name + '!';
~>  res.send(nunjucks.renderString(tpl, {}));
};

exports.custom = function custom(req, res) {
  const { body } = req.body;
~>  const out = ejs.render(
    body,
    { now: Date.now() },
  );
  res.send(out);
};
