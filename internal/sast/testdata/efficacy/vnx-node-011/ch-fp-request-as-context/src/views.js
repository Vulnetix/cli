const ejs = require('ejs');
const nunjucks = require('nunjucks');

exports.profile = (req, res) => {
  res.render('profile', { name: req.query.name, bio: req.body.bio });
};

exports.mail = async (req, res) => {
  const html = await ejs.renderFile('views/mail.ejs', { user: req.body });
  const page = nunjucks.render('page.html', req.query);
  res.send(html + page);
};
