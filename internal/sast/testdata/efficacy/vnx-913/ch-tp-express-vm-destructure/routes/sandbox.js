const vm = require("vm");
const router = require("express").Router();

router.post("/run", (req, res) => {
  const { script, timeout } = req.body;
  const ctx = vm.createContext({ console });
~>  const out = vm.runInContext(script, ctx, { timeout: 500 });
  res.json({ out });
});

module.exports = router;
