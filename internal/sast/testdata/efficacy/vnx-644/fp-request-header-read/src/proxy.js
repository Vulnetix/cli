function forward(req, res) {
  const auth = req.headers.authorization;
  req.headers['x-forwarded-for'] = req.ip;
  res.status(200).json({ ok: Boolean(auth), q: req.query.q });
  res.set('Vary', 'Accept-Encoding');
}
