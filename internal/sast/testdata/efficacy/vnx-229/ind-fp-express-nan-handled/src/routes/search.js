const router = require("express").Router();

router.get("/search", async (req, res) => {
  const size = Number(req.query.size) || 20;
  const offset = parseInt(req.query.offset, 10) ?? 0;
  const n = parseInt(req.query.n, 10);
  if (Number.isNaN(n)) {
    return res.status(400).json({ error: "n must be a number" });
  }
  res.json(await search(req.query.q, size, offset, n));
});

module.exports = router;
