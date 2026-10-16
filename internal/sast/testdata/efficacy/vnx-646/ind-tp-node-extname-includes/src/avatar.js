const path = require('path');
app.post('/avatar', upload.single('avatar'), (req, res) => {
  const ext = path.extname(req.file.originalname).toLowerCase();
~>  if (!['.png', '.jpg'].includes(ext)) {
    return res.status(400).send('bad type');
  }
  res.send('ok');
});
