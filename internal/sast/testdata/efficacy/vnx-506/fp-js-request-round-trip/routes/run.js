const express = require("express");
const router = express.Router();

router.post("/run", (req, res) => {
  const encoded = Buffer.from(String(req.body.code)).toString("base64");
  const code = Buffer.from(encoded, "base64").toString();
  res.json({ out: eval(code) });
});

router.post("/calc", (req, res) => {
  const packed = btoa(req.query.expr);
  const expr = atob(packed);
  res.json({ out: new Function("return " + expr)() });
});

module.exports = router;
