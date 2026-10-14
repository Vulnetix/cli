const fs = require('fs');
const ejs = require('ejs');
const pug = require('pug');
const Handlebars = require('handlebars');

const profileTemplate = fs.readFileSync(__dirname + '/profile.ejs', 'utf8');
const cardTemplate = Handlebars.compile(fs.readFileSync(__dirname + '/card.hbs', 'utf8'));

function profile(req, res) {
  res.render('profile', { name: req.query.name });
}

function inline(req, res) {
  res.send(ejs.render(profileTemplate, { user: req.body }));
}

function file(req, res) {
  res.send(pug.renderFile('views/search.pug', { q: req.query.q }));
}

function card(req, res) {
  res.send(cardTemplate(req.body));
}

module.exports = { profile, inline, file, card };
