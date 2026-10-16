const express = require("express");
const Member = require("../models/member");

const router = express.Router();

router.post("/register", async (req, res) => {
  const member = new Member({ email: req.body.email, password: req.body.password });
  await member.save();
  res.status(201).end();
});

module.exports = router;
