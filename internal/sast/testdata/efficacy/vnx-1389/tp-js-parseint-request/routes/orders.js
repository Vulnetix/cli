const express = require("express");
const router = express.Router();

router.get("/orders", (req, res) => {
~>  const page = parseInt(req.query.page);
~>  const limit = Number.parseInt( req.query.limit );
  res.json(listOrders(page, limit));
});

router.post("/transfer", (req, res) => {
~>  const amount = parseInt(req.body.amount) || 0;
  res.json(transfer(req.user, amount));
});

module.exports = router;
