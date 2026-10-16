const path = require('path');

app.post('/upload', upload.single('doc'), (req, res) => {
  const ext = path.extname(req.file.originalname);
~>  if (['.php', '.jsp', '.html'].includes(ext)) {
    return res.status(400).end();
  }
  res.sendStatus(201);
});
