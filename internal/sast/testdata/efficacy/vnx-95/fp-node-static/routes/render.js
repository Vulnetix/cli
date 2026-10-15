const ejs = require('ejs');
const fs = require('fs');
const Handlebars = require('handlebars');

const layout = fs.readFileSync('views/layout.ejs', 'utf8');

module.exports = function (app) {
  app.get('/page', (req, res) => {
    res.send(ejs.render(layout, { name: req.query.name }));
  });
  app.get('/view', (req, res) => {
    res.render('profile', { user: req.query.user });
  });
  app.get('/hbs', (req, res) => {
    const t = Handlebars.compile('<p>{{msg}}</p>');
    // Handlebars.compile(req.query.msg) would allow SSTI
    res.send(t({ msg: req.query.msg }));
  });
};
