const { fileTypeFromBuffer } = require('file-type');
const path = require('path');

router.post('/img', upload.single('img'), async (req, res) => {
  const type = await fileTypeFromBuffer(req.file.buffer);
  if (!type || !['image/png', 'image/jpeg'].includes(type.mime)) {
    return res.sendStatus(415);
  }
  if (!/\.(png|jpe?g)$/i.test(req.file.originalname)) {
    return res.sendStatus(415);
  }
  res.sendStatus(204);
});
