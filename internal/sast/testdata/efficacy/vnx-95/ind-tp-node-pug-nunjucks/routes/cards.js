const pug = require('pug');
const nunjucks = require('nunjucks');

module.exports = (app) => {
  app.post('/cards/render', (req, res) => {
~>    const html = pug.render(req.body.layout, { user: req.user });
    res.send(html);
  });

  app.get('/cards/title', (req, res) => {
~>    const fn = pug.compile(`h1 ${req.query.title}`);
    res.send(fn({}));
  });

  app.post('/emails/preview', (req, res) => {
    const tpl = req.body.template;
~>    const out = nunjucks.renderString(tpl, { name: 'Ada' });
    res.send(out);
  });
};
