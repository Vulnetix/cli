const express = require('express');
const router = express.Router();

router.get('/plugin', (req, res) => {
~>  const plugin = require(req.query.name);
  res.json(plugin.describe());
});

module.exports = router;
