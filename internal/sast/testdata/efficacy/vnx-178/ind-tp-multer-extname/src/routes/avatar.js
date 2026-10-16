const path = require('path');
const multer = require('multer');
const express = require('express');

const router = express.Router();
const upload = multer({ dest: 'public/uploads/' });

router.post('/avatar', upload.single('avatar'), (req, res) => {
  const ext = path.extname(req.file.originalname);
~>  if (ext === '.php' || ext === '.jsp' || ext === '.html') {
    return res.status(400).json({ error: 'unsupported file' });
  }
  res.json({ url: `/uploads/${req.file.filename}${ext}` });
});

module.exports = router;
