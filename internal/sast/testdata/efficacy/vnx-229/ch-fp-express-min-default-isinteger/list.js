const express = require("express");
const router = express.Router();

router.get("/list", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  const page = Number(req.query.page);
  if (!Number.isInteger(page) || page < 1) {
    return res.status(400).json({ error: "page must be a positive integer" });
  }
  res.json(paginate(limit, page));
});

module.exports = router;
