const router = require("express").Router();
const Account = require("../models/account");

router.get("/account/:id", async (req, res) => {
  const account = await Account.findById(req.params.id);
~>  res.json(account);
});

module.exports = router;
