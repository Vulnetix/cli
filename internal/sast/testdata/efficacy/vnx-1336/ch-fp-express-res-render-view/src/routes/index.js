const router = require('express').Router();

router.get('/', (req, res) => {
  res.render('index', { title: req.query.title });
});

router.get('/hbs', (req, res) => {
  const tmpl = Handlebars.compile('<p>{{name}}</p>');
  res.send(tmpl({ name: req.query.name }));
});

module.exports = router;
