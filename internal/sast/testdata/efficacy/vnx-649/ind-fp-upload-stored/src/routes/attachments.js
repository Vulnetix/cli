const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const router = express.Router();

router.post('/attachments', async (req, res) => {
  const bytes = Buffer.from(req.body.data, 'base64');
  const name = crypto.randomUUID();
  await fs.writeFile(path.join('/srv/attachments', name), bytes);
  res.status(201).json({ id: name });
});

module.exports = router;
