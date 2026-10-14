const { spawn } = require('child_process');
const express = require('express');

const app = express();

app.post('/convert', (req, res) => {
  const file = req.body.file;
~>  const child = spawn('convert', [file, 'out.png'], { shell: true });
  child.on('close', (code) => res.json({ code }));
});
