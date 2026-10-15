function merge(a, b) {
  return a.concat(b);
}

export function update(req, res) {
  const claims = req.user;
  const tags = merge(claims.tags, ["new"]);
  const profile = Object.assign({}, { name: req.body.name });
  res.json({ tags, profile });
}
