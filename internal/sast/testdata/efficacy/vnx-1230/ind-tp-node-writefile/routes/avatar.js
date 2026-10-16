const express = require('express');
const fs = require('fs');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });
const router = express.Router();

router.post('/avatar', upload.single('avatar'), async (req, res) => {
  if (!req.file.mimetype.startsWith('image/')) return res.sendStatus(415);
~>  fs.writeFileSync(`public/avatars/${req.user.id}.jpg`, req.file.buffer);
  res.json({ ok: true });
});
module.exports = router;
