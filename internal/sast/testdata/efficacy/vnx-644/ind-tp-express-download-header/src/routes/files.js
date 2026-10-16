const express = require('express');
const path = require('path');
const router = express.Router();

router.get('/download/:name', (req, res) => {
  const filePath = path.join('/srv/exports', path.basename(req.params.name));
~>  res.setHeader('Content-Disposition', `attachment; filename="${req.params.name}"`);
  res.sendFile(filePath);
});

router.get('/tag', (req, res) => {
~>  res.set('X-Client-Tag', req.query.tag);
  res.end();
});

module.exports = router;
