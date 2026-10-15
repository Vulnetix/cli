const { execFileSync } = require('child_process');

router.get('/thumb', (req, res) => {
  const file = req.query.file;
~>  execFileSync('convert', [file, '-resize', '64x64', 'out.png'], { shell: true });
  res.sendFile('out.png');
});
