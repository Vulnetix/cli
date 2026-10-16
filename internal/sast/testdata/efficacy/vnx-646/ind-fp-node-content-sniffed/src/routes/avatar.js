const express = require('express');
const multer = require('multer');
const path = require('path');
const { fileTypeFromBuffer } = require('file-type');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/avatar', upload.single('avatar'), async (req, res) => {
  const ext = path.extname(req.file.originalname).toLowerCase();
  if (!['.png', '.jpg'].includes(ext)) {
    return res.status(400).send('png or jpg');
  }
  const type = await fileTypeFromBuffer(req.file.buffer);
  if (!type || !['image/png', 'image/jpeg'].includes(type.mime)) {
    return res.status(400).send('not an image');
  }
  await saveAvatar(req.user.id, req.file.buffer, type.ext);
  res.sendStatus(204);
});

module.exports = router;
