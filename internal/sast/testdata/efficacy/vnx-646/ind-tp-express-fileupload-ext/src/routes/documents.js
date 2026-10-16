const express = require('express');
const fileUpload = require('express-fileupload');
const path = require('path');

const router = express.Router();
router.use(fileUpload());

const ALLOWED = ['.pdf', '.docx', '.txt'];

router.post('/documents', async (req, res) => {
  const doc = req.files.document;
  const ext = path.extname(doc.name).toLowerCase();
~>  if (!ALLOWED.includes(ext)) {
    return res.status(400).json({ error: 'unsupported file type' });
  }
  await doc.mv(path.join('/srv/uploads', `${Date.now()}${ext}`));
  res.status(201).json({ ok: true });
});

module.exports = router;
