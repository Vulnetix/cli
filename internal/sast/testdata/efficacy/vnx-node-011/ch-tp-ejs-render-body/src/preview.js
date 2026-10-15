const ejs = require('ejs');

exports.preview = (req, res) => {
~>  const html = ejs.render(req.body.template, { user: req.user });
  res.send(html);
};
