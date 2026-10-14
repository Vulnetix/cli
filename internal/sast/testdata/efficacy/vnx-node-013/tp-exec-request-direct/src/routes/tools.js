const express = require('express');
const child_process = require('child_process');
const { exec, execSync } = require('child_process');

const router = express.Router();

router.get('/ping', (req, res) => {
~>  exec('ping -c 1 ' + req.query.host, (err, stdout) => res.send(stdout));
});

router.post('/log', (req, res) => {
~>  const out = execSync(`git log --oneline ${req.body.ref}`);
  res.send(out.toString());
});

router.post('/run', (req, res) => {
~>  child_process.exec(req.body.cmd, (err, stdout) => res.send(stdout));
});

module.exports = router;
