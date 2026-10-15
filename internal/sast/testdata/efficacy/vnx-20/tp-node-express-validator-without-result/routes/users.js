const express = require('express');
const { body, param } = require('express-validator');
const User = require('../models/user');

const router = express.Router();

router.post(
  '/register',
~>  body('email').isEmail().normalizeEmail(),
~>  body('password').isLength({ min: 12 }),
  async (req, res) => {
    const user = await User.create(req.body);
    res.status(201).json(user);
  }
);

~>router.delete('/:id', param('id').isMongoId(), async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

module.exports = router;
