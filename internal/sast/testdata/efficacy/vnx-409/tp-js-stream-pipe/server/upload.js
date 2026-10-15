const zlib = require('zlib');
const fs = require('fs');

app.post('/upload', (req, res) => {
  const out = fs.createWriteStream('/tmp/upload.bin');
~>  req.pipe(zlib.createGunzip()).pipe(out);
  out.on('finish', () => res.sendStatus(201));
});
