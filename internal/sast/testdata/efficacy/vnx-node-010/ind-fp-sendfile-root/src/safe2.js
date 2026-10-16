const PUBLIC_DIR = '/srv/public';

app.get('/assets/:name', (req, res) => {
  res.sendFile(req.params.name, { root: PUBLIC_DIR });
});
