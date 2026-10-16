const express = require('express');
const { listWidgets } = require('../services/widgets');

const router = express.Router();

router.get('/api/widgets.js', async (req, res) => {
  const rows = await listWidgets();
  res.set('Content-Type', 'application/javascript');
~>  res.send(req.query.callback + '(' + JSON.stringify(rows) + ');');
});

module.exports = router;
