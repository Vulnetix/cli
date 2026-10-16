const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const express = require('express');

const router = express.Router();

router.put('/logs/:name', (req, res) => {
  const out = fs.createWriteStream(path.join('/var/lib/logs', path.basename(req.params.name)));
~>  req.pipe(zlib.createGunzip()).pipe(out);
  out.on('finish', () => res.sendStatus(201));
  out.on('error', () => res.sendStatus(500));
});

module.exports = router;
