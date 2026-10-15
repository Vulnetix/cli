const ejs = require('ejs');
const Handlebars = require('handlebars');

const CARD = Handlebars.compile('<div>{{title}}</div>');
const ROW = '<tr><td><%= name %></td></tr>';

module.exports.profile = (req, res) => {
  res.render('profile', { bio: req.body.bio });
};

module.exports.row = (req, res) => {
  res.send(ejs.render(ROW, { name: req.query.name }));
};

module.exports.card = (req, res) => {
  res.send(CARD({ title: req.query.title }));
};

module.exports.file = (req, res) => {
  ejs.renderFile('views/list.ejs', { q: req.query.q }, (err, html) => res.send(html));
};
