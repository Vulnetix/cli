const express = require('express');
const zlib = require('zlib');
const { buildExport } = require('../lib/export');

const router = express.Router();

router.get('/export', async (req, res) => {
  const data = await buildExport(req.user.id);
  const body = zlib.gzipSync(Buffer.from(JSON.stringify(data)));
  res.set('Content-Encoding', 'gzip').send(body);
});

router.get('/export/stream', (req, res) => {
  res.set('Content-Encoding', 'gzip');
  buildExport.stream(req.user.id).pipe(zlib.createGzip()).pipe(res);
});

module.exports = router;
