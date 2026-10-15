const router = require('express').Router();

router.get('/export', (req, res) => {
  const fmt = req.query.format === 'csv' ? require('./csv') : require('./json');
  res.send(fmt.render(req.query));
});

module.exports = router;
