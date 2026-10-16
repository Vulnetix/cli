const express = require('express');
const knex = require('../knex');
const router = express.Router();

router.get('/users/:id', async (req, res) => {
~>  const rows = await knex.raw('SELECT id, name FROM users WHERE id = ?', [req.params.id]);
  res.json(rows);
});

module.exports = router;
