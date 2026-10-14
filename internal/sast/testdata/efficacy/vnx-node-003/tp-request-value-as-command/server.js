const childProcess = require('child_process');
const express = require('express');
const app = express();

app.post('/run', (req, res) => {
  const command = req.body.command;
~>  childProcess.exec(command, (e, stdout) => res.send(stdout));
});
