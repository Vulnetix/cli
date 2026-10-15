const fs = require('fs');
const path = require('path');
const express = require('express');
const router = express.Router();

router.get('/files', function (req, res) {
  const dir = path.join(__dirname, '..', 'uploads');
~>  const names = fs.readdirSync(dir);
  res.json(names);
});

module.exports = router;
