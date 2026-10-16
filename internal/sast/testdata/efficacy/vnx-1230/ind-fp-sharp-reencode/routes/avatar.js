const fs = require('fs');
const sharp = require('sharp');

async function handle(req, res) {
  if (!req.file.mimetype.startsWith('image/')) return res.sendStatus(415);
  const clean = await sharp(req.file.buffer).rotate().jpeg().toBuffer();
  fs.writeFileSync(`public/avatars/${req.user.id}.jpg`, clean);
  res.sendStatus(204);
}
module.exports = handle;
