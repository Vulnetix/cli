const pug = require('pug');

exports.greet = (req, res) => {
~>  const html = pug.render(`h1 Hello #{name}\np ${req.query.message}`, { name: 'guest' });
  res.send(html);
};
