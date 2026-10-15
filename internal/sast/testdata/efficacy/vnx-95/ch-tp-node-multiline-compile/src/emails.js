const Handlebars = require('handlebars');
const pug = require('pug');
const ejs = require('ejs');

module.exports.preview = (req, res) => {
  const layout = req.body.layout;
~>  const render = Handlebars.compile(
    layout,
    { noEscape: false }
  );
  res.send(render({ name: req.user.name }));
};

module.exports.banner = (req, res) => {
~>  res.send(pug.render(`h1 ${req.query.title}`));
};

module.exports.note = (req, res) => {
~>  const out = ejs.render('<p>' + req.body.note + '</p>', {});
  res.send(out);
};
