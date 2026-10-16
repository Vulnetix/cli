const router = require('express').Router();

router.post('/theme', (req, res) => {
  const theme = req.body.theme;
~>  const renderer = require('./themes/' + theme);
  res.send(renderer.render());
});
module.exports = router;
