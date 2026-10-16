const pug = require('pug');

router.get('/p', (req, res) => {
  res.set('Content-Type', 'text/html');
~>  res.send(pug.render(req.query.tpl));
});
