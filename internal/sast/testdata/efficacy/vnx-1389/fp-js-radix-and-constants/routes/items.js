const router = require("express").Router();

router.get("/items", (req, res) => {
  const page = parseInt(req.query.page, 10);
  const limit = Number.parseInt(req.query.limit, 10);
  const size = Number(req.query.size);
  const fixed = parseInt("42");
  const width = parseInt(style.width);
  const count = parseInt(items.length);
  res.json({ page, limit, size, fixed, width, count });
});

module.exports = router;
