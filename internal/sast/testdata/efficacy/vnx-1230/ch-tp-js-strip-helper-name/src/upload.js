const fs = require('fs/promises');
const { stripTrailingSlash } = require('./util');

async function saveAvatar(req, res) {
  const base = stripTrailingSlash(process.env.AVATAR_DIR);
  if (!req.file.mimetype.startsWith('image/')) return res.sendStatus(415);
~>  await fs.writeFile(`${base}/${req.user.id}.png`, req.file.buffer);
  res.sendStatus(204);
}

module.exports = { saveAvatar };
