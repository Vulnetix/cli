const mailer = require("../mailer");

router.post("/welcome", async (req, res) => {
  const { name, email } = req.body;
  const text = `Hello ${name}, thanks for signing up. Your prompt access starts today.`;
  await mailer.send({ to: email, subject: "Welcome", text });
  res.sendStatus(204);
});
