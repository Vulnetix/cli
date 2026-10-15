app.post("/login", (req, res) => {
  const email = req.body.email;
  if (typeof email !== "string") return res.sendStatus(400);
  const normalized = email.trim().toLowerCase();
  const q = String(req.query.q).split(" ");
  const raw = req.query.term;
  const term = Array.isArray(raw) ? raw[0] : raw;
  res.json(find(normalized, q, term));
});
