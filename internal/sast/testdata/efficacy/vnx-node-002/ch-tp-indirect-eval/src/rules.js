const express = require("express");
const router = express.Router();

router.post("/rules/test", (req, res) => {
  const expression = req.body.expression;
~>  const result = (0, eval)(expression);
  res.json({ result });
});

router.get("/calc", (req, res) => {
~>  res.send(String(globalThis.eval(req.query.q)));
});

module.exports = router;
