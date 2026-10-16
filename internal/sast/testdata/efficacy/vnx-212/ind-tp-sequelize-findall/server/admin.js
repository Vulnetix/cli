const { Router } = require('express');
const { User } = require('../models');

const admin = Router();

admin.get('/users', async (req, res) => {
  const users = await User.findAll({ where: { orgId: req.user.orgId } });
~>  res.send({ users });
});

module.exports = admin;
