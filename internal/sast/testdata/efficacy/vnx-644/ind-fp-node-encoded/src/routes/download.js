const express = require('express');
const contentDisposition = require('content-disposition');
const router = express.Router();

router.get('/files/:name', (req, res) => {
  res.setHeader('Content-Disposition', contentDisposition(req.params.name));
  res.set('X-Query', encodeURIComponent(req.query.q || ''));
  res.set('X-Page', String(parseInt(req.query.page, 10) || 1));
  const tag = String(req.query.tag || '').replace(/[\r\n]/g, '');
  res.set('X-Tag', tag);
  res.setHeader('Cache-Control', 'no-store');
  res.end();
});

module.exports = router;
