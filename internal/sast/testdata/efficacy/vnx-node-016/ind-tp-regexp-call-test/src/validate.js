app.post('/check', (req, res) => {
~>  const ok = RegExp(req.body.rule, 'i').test(req.body.value);
  res.json({ ok });
});
