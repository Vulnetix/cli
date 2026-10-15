router.post("/import", (req, res) => {
  const raw = req.body.payload;
  const data = JSON.parse(raw);
  const evaluateRules = (d) => d.rules.length;
  const n = evaluateRules(data);
  const safe = Function.prototype.call.bind(String.prototype.trim);
  res.json({ n, name: safe(req.body.name) });
});
