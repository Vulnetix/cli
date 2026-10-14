const nunjucks = require('nunjucks');
const ejs = require('ejs');

function greet(req, res) {
  res.send(nunjucks.renderString('Hello {{ name }}', { name: req.query.name }));
}

function welcome(req, res) {
  const out = ejs.render('<p><%= user %></p>', { user: req.body.user });
  res.send(out);
}

module.exports = { greet, welcome };
