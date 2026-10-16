const express = require('express');
const router = express.Router();

// A query or body value used as a string in JavaScript is this rule's
// finding; VNX-241 reads Python JSON bodies and leaves it here.
router.get('/download', (req, res) => {
  const name = req.query.name;
~>  if (name.indexOf('..') !== -1) {
    return res.status(400).end();
  }
~>  const ext = req.query.ext.toLowerCase();
  res.sendFile(`/srv/files/${name}.${ext}`);
});

router.post('/rename', (req, res) => {
  const { title } = req.body;
~>  const clean = title.trim();
~>  res.json({ title: clean, length: req.body.title.length });
});

module.exports = router;
