const express = require('express');
const yaml = require('js-yaml');

const router = express.Router();

router.post('/config', express.text({ type: '*/yaml' }), (req, res) => {
~>  const cfg = yaml.load(req.body);
  res.json(cfg);
});

router.post('/upload', upload.single('file'), (req, res) => {
  const text = req.file.buffer.toString('utf8');
~>  const docs = yaml.loadAll(text);
  res.json({ count: docs.length });
});

module.exports = router;
