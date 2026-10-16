const fs = require('fs');
const path = require('path');
const ejs = require('ejs');
const Handlebars = require('handlebars');
const pug = require('pug');

const views = path.join(__dirname, '..', 'views');
const receipt = Handlebars.compile(fs.readFileSync(path.join(views, 'receipt.hbs'), 'utf8'));
const greet = pug.compileFile(path.join(views, 'greet.pug'));

module.exports = (app) => {
  app.get('/search', (req, res) => {
    ejs.renderFile(path.join(views, 'search.ejs'), { q: req.query.q }, (err, html) => {
      if (err) return res.sendStatus(500);
      res.send(html);
    });
  });

  app.get('/receipt', (req, res) => res.send(receipt({ order: req.query.order })));
  app.get('/greet', (req, res) => res.send(greet({ name: req.query.name })));
  app.get('/layout', (req, res) => res.send(ejs.render(LAYOUT, { title: req.query.title })));
};

const LAYOUT = '<title><%= title %></title>';
