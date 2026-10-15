exports.validate = (req, res) => {
  const ok = req.query.slug.match(/^[a-z0-9-]+$/);
  const parts = req.body.date.match(new RegExp('^(\\d{4})-(\\d{2})$'));
  res.json({ ok: !!ok, parts });
};
