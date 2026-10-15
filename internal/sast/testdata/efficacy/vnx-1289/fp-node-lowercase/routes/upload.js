const path = require('path');

router.post('/avatar', (req, res) => {
  const ext = path.extname(req.file.originalname).toLowerCase();
  if (['.php', '.exe'].includes(ext)) {
    return res.status(400).end();
  }
  if (!req.file.originalname.toLowerCase().endsWith('.zip')) {
    return res.status(400).end();
  }
  if (file.endsWith('.js')) {
    require(file);
  }
  res.end();
});
