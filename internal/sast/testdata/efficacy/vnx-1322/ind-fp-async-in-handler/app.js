const fs = require('fs');
const { execFile } = require('child_process');
const app = require('express')();
app.get('/f/:n', async (req, res) => {
  const body = await fs.promises.readFile('/data/' + req.params.n, 'utf8');
  fs.readFile('/tmp/x', (err, d) => {});
  execFile('uptime', (err, stdout) => res.send(body + stdout));
});
