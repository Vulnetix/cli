const ALLOWED = ['.png', '.jpg', '.gif'];
app.post('/avatar', upload.single('img'), (req, res) => {
  const ext = path.extname(req.file.originalname);
  if (!ALLOWED.includes(ext)) return res.status(400).end();
  const name = req.file.originalname.toLowerCase();
  if (name.endsWith('.php')) return res.status(400).end();
  res.sendStatus(201);
});
