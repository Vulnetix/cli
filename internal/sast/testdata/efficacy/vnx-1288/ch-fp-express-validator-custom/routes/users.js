const { body, validationResult } = require('express-validator');
const router = require('express').Router();

router.post(
  '/users',
  body('password').isLength({ min: 12 }),
  body('passwordConfirmation').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Password confirmation does not match password');
    }
    return true;
  }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json(errors.array());
    await saveUser(req.body.email, req.body.password);
    res.sendStatus(201);
  }
);

module.exports = router;
