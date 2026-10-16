app.post('/run', (req, res) => {
  const out = eval(req.query.expr);
  const v = vm.runInNewContext(req.body.script, {});
  res.json({ out, v });
});
