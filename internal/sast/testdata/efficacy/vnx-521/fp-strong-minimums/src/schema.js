const schema = Joi.object({
  password: Joi.string().min(12).max(128).required(),
});
const rules = [body("password").isLength({ min: 10 })];
if (password.length < 8) {
  throw new Error("Password must be at least 8 characters");
}
