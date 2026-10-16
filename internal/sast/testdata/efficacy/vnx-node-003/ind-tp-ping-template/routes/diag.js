const { exec } = require('child_process');
const express = require('express');
const router = express.Router();

router.get('/ping', (req, res) => {
~>  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
    if (err) return res.status(500).send('failed');
    res.type('text/plain').send(stdout);
  });
});

module.exports = router;
