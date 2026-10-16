const { spawn } = require('child_process');
const router = require('express').Router();

router.post('/convert', (req, res) => {
  const input = req.body.filename;
~>  const child = spawn('ffmpeg', ['-i', input, '-vf', 'scale=640:-1', 'out.mp4'], { shell: true });
  child.on('close', (code) => res.json({ code }));
});

module.exports = router;
