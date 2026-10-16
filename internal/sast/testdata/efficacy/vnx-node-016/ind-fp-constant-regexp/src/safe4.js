const HEX = new RegExp('^[0-9a-f]{8}$');
app.get('/h', (req, res) => {
  res.json({ ok: HEX.test(req.query.h) });
});
