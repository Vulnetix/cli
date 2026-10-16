const { execFile, spawn } = require('child_process');

app.get('/ping', (req, res) => {
  execFile('ping', ['-c', '1', req.query.host], (err, out) => res.send(out));
});
app.get('/log', (req, res) => {
  const p = spawn('git', ['log', req.query.ref]);
  p.stdout.pipe(res);
});
