const pug = require('pug');
const Handlebars = require('handlebars');
const router = require('express').Router();

router.post('/pug', (req, res) => {
~>  res.send(pug.render(req.body.src));
});

router.get('/hbs', (req, res) => {
~>  const html = Handlebars.compile(req.query.t)({ user: req.user });
  res.send(html);
});

module.exports = router;
