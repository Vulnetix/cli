const fs = require('fs/promises');
const sharp = require('sharp');

module.exports = async (req, res) => {
  if (!req.file.mimetype.startsWith('image/')) return res.sendStatus(415);
  // sharp drops EXIF/GPS unless withMetadata() is called
  const clean = await sharp(req.file.buffer).rotate().jpeg().toBuffer();
  await fs.writeFile(`public/avatars/${req.user.id}.jpg`, clean);
  res.sendStatus(201);
};
