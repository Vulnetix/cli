const express = require("express");
const router = express.Router();

router.post("/cart", (req, res) => {
~>  const qty = Number.parseInt(req.body.quantity, 10);
  const items = req.session.cart.slice(0, qty);
  res.json({ items });
});

module.exports = router;
