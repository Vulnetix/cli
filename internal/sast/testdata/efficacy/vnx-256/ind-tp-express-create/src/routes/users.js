const express = require("express");
const User = require("../models/user");
const { getDb } = require("../db");

const router = express.Router();

router.post("/signup", async (req, res, next) => {
  try {
~>    const user = new User({ email: req.body.email, password: req.body.password });
    await user.save();
    res.status(201).json({ id: user.id });
  } catch (err) {
    next(err);
  }
});

router.post("/admin/users", async (req, res) => {
  const { email, password } = req.body;
~>  await getDb().collection("users").insertOne({ email, password: password, role: "staff" });
  res.sendStatus(201);
});

module.exports = router;
