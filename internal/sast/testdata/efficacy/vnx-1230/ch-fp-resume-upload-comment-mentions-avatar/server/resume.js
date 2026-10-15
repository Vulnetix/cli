const express = require('express');
const multer = require('multer');
const fs = require('fs');

// Profile pictures are handled in avatar.js, which re-encodes them.
const upload = multer({ storage: multer.memoryStorage() });
const router = express.Router();

router.post('/careers/resume', upload.single('resume'), (req, res) => {
  if (req.file.mimetype !== 'application/pdf') {
    return res.status(415).send('PDF only');
  }
  fs.writeFileSync(`/srv/resumes/${req.user.id}.pdf`, req.file.buffer);
  res.sendStatus(201);
});

module.exports = router;
