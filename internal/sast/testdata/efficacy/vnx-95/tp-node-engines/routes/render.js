const ejs = require('ejs');
const pug = require('pug');
const Handlebars = require('handlebars');
const nunjucks = require('nunjucks');
const _ = require('lodash');

module.exports = function (app) {
  app.get('/ejs', (req, res) => {
~>    res.send(ejs.render(req.query.tpl, {}));
  });
  app.post('/pug', (req, res) => {
~>    const fn = pug.compile(req.body.layout);
    res.send(fn({}));
  });
  app.post('/hbs', (req, res) => {
~>    const t = Handlebars.compile(`<div>${req.body.msg}</div>`);
~>    const n = nunjucks.renderString(req.body.page, { user: req.user });
~>    const l = _.template(req.query.banner);
    res.send(t({}) + n + l({}));
  });
};
