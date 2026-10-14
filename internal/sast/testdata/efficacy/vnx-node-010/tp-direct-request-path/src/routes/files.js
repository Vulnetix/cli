const fs = require('fs');
const path = require('path');
const express = require('express');

const router = express.Router();

router.get('/read', (req, res) => {
~>  fs.readFile(req.query.file, 'utf8', (err, text) => res.send(text));
});

router.get('/raw/:name', (req, res) => {
~>  const body = fs.readFileSync('./uploads/' + req.params.name);
  res.send(body);
});

router.get('/doc/:name', (req, res) => {
~>  res.sendFile(path.join(__dirname, 'docs', req.params.name));
});

router.get('/download', (req, res) => {
~>  res.download(req.query.path);
});

module.exports = router;
