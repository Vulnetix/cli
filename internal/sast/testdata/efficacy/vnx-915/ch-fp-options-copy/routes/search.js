router.get("/search", async (req, res) => {
  const opts = Object.assign({}, DEFAULT_OPTS, req.query);
  const url = new URL(req.query.next, BASE);
  const results = await index.search(opts);
  res.json(results);
});
