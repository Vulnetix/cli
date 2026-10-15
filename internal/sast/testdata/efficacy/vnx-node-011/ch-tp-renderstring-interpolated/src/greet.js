const nunjucks = require('nunjucks');

exports.greet = (req, res) => {
~>  const html = nunjucks.renderString(`<h1>Hello ${req.query.name}</h1>`, { site: 'Shop' });
  res.send(html);
};
