const express = require("express");
const vm = require("vm");
const router = express.Router();

router.post("/score", (req, res) => {
  const { label, formula, weight: factor } = req.body;
~>  const score = vm.runInNewContext(formula, { x: 1 });
~>  const scaled = eval(factor);
  res.json({ label, score, scaled });
});

module.exports = router;
