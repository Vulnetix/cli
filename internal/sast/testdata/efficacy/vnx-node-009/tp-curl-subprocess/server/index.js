const express = require('express');
const { spawnSync, execFile } = require('child_process');

const app = express();
app.use(express.json());

app.post('/fetch', (req, res) => {
  var endpoint = req.body.endpoint, method = req.body.method || 'GET';
~>  const child = spawnSync('curl', ['-s', '-X', method, endpoint]);
  res.send(child.stdout);
});

app.get('/download', (req, res) => {
~>  execFile('wget', ['-qO-', req.query.link], (err, out) => res.send(out));
});

app.listen(3000);
