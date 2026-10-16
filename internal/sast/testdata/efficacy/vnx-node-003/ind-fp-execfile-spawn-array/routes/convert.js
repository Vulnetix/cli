const { execFile, spawn, execSync } = require('child_process');

const ALLOWED = /^[a-zA-Z0-9_-]+\.(jpg|png)$/;

function convert(req, res) {
  if (!ALLOWED.test(req.query.file)) return res.status(400).end();
  execFile('convert', [req.query.file, 'out.png'], (err) => {
    if (err) return res.status(500).end();
    res.sendFile('out.png');
  });
  const p = spawn('ffmpeg', ['-i', req.query.file, 'out.mp4']);
  p.on('close', () => {});
  const rev = execSync('git rev-parse HEAD').toString().trim();
  return rev;
}

module.exports = convert;
