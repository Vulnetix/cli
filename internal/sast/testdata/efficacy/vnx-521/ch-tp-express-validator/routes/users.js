const { body } = require("express-validator");

router.post(
  "/register",
  body("email").isEmail(),
~>  body("password").isLength({ min: 5 }),
  register
);
