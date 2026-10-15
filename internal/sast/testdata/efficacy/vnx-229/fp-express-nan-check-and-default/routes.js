router.get("/items", (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const size = Number(req.query.size ?? 20) ?? 20;
  const limit = parseInt(req.query.limit, 10);
  if (Number.isNaN(limit)) {
    return res.status(400).send("bad limit");
  }
  const offset = parseFloat(req.body.offset);
  if (!Number.isFinite(offset)) return res.sendStatus(400);
  res.json(paginate(page, size, limit, offset));
});
