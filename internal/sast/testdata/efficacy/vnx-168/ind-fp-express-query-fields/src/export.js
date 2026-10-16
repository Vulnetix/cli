const express = require('express');
const { stringify } = require('./serialize');

const router = express.Router();

router.get('/users/export.csv', async (req, res) => {
  const fields = (req.query.fields || 'id,name,email').split(',');
  const users = await req.db.users.findAll({ attributes: fields });
  res.type('text/csv');
  res.send(stringify(users, fields));
});

module.exports = router;
