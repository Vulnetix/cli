const express = require("express");
const router = express.Router();

router.post("/reset", async (req, res) => {
  const user = await User.findById(req.user.id);
~>  user.password = req.body.newPassword;
  await user.save();
  res.sendStatus(204);
});
