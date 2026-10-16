const fs = require('fs');
const path = require('path');
const express = require('express');

const router = express.Router();

router.get('/read', (req, res) => {
~>  fs.readFile(req.query.file, 'utf8', (err, data) => res.send(data));
});

router.get('/download/:name', (req, res) => {
  const p = path.join(__dirname, 'uploads', req.params.name);
~>  res.download(p);
});

router.post('/render', (req, res) => {
  const { template } = req.body;
~>  res.send(fs.readFileSync(`views/${template}.html`, 'utf8'));
});

router.get('/file', (req, res) => {
~>  res.sendFile(path.join(__dirname, req.query.f));
});

module.exports = router;
