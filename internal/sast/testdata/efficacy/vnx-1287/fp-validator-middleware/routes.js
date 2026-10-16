const { body, validationResult } = require("express-validator");

router.post("/signup", body("email").isEmail(), body("name").isString(), (req, res) => {
  if (!validationResult(req).isEmpty()) return res.sendStatus(400);
  const email = req.body.email.toLowerCase();
  res.json(register(email, req.body.name.trim()));
});
