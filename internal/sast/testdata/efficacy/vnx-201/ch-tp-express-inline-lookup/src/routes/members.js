const router = require("express").Router();
const Member = require("../models/member");

router.get("/members/:id", async (req, res) => {
~>  res.json(await Member.findById(req.params.id));
});

router.get("/members/:id/card", async (req, res) => {
  res.json(await Member.findById(req.params.id).select("name avatar"));
});

module.exports = router;
