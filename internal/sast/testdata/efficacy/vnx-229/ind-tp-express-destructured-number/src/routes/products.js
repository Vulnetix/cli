const router = require("express").Router();

router.get("/products", async (req, res) => {
  const { page } = req.query;
~>  const p = Number(page);
  const rows = await db.query("SELECT * FROM products ORDER BY id LIMIT 20 OFFSET $1", [p * 20]);
  res.json(rows);
});

module.exports = router;
