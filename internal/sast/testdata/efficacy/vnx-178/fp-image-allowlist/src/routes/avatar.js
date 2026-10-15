const path = require('path');

function uploadAvatar(req, res) {
  const ext = path.extname(req.file.originalname);
  if (!['.png', '.jpg', '.gif'].includes(ext)) {
    return res.status(400).send('images only');
  }
  if (req.file.originalname.endsWith('.png')) {
    res.type('image/png');
  }
  res.send('ok');
}

module.exports = { uploadAvatar };
