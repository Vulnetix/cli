const path = require('path');

router.post('/avatar', upload.single('avatar'), (req, res) => {
~>  if (req.file.originalname.endsWith('.exe')) {
    return res.status(400).end();
  }
  const ext = path.extname(req.file.originalname);
~>  if (['.php', '.jsp', '.html'].includes(ext)) {
    return res.status(400).end();
  }
~>  if (ext === '.svg') return res.status(415).end();
  res.json({ ok: true });
});
