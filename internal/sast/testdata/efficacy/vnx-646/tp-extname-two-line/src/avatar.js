const path = require('path');

router.post('/avatar', upload.single('avatar'), (req, res) => {
  const ext = path.extname(req.file.originalname).toLowerCase();
  const fileType = req.file.originalname.substr(req.file.originalname.lastIndexOf('.') + 1);
~>  if (!['.png', '.jpg'].includes(ext)) {
    return res.status(400).send('bad type');
  }
~>  const ok = ALLOWED.indexOf(fileType) !== -1;
  store(req.file.path, ok);
  res.sendStatus(204);
});
