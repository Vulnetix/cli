const re = /(\d+)-(\d+)/;

app.get('/range', (req, res) => {
  const m = re.exec(req.query.r);
  const rows = db.exec('SELECT 1');
  res.json({ m, rows });
});
