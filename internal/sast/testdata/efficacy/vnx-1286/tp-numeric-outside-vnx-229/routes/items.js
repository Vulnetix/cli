const express = require("express");

const router = express.Router();

router.get("/items/:id", async (req, res) => {
~>  const id = parseInt(req.params.id, 10);
  const item = await Item.findByPk(id);
  res.json(item);
});

router.get("/items/:id/page/:n", async (req, res) => {
  const n = parseInt(req.params.n, 10) || 1;
  res.json(await Item.page(n));
});

module.exports = router;
