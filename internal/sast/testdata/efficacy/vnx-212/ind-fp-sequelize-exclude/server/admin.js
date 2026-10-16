const { Router } = require('express');
const { User } = require('../models');

const admin = Router();

admin.get('/users', async (req, res) => {
  const users = await User.findAll({
    where: { orgId: req.user.orgId },
    attributes: { exclude: ['password', 'resetToken'] },
  });
  res.json(users);
});

admin.get('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  const { password, ...safe } = user.get({ plain: true });
  res.json(safe);
});

module.exports = admin;
