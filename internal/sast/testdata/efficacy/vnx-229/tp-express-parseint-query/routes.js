const express = require("express");
const router = express.Router();

router.get("/items", async (req, res) => {
~>  const limit = parseInt(req.query.limit, 10);
~>  const items = await Item.find().skip(Number(req.query.offset)).limit(limit);
  res.json(items);
});

module.exports = router;
