const crypto = require("crypto");

router.post("/forgot", async (req, res) => {
  const token = crypto.randomBytes(32).toString("hex");
  await User.updateOne({ email: req.body.email }, { resetPasswordToken: token });
~>  const resetLink = `${req.protocol}://${req.get("host")}/reset/${token}`;
  await mailer.send(req.body.email, resetLink);
  res.sendStatus(204);
});
