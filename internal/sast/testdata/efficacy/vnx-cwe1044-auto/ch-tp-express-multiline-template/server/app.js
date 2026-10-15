const express = require('express');
const { Pool } = require('pg');

const pool = new Pool();
const app = express();

app.get('/orders/:id', async (req, res) => {
~>  const { rows } = await pool.query(`
    SELECT o.id, o.total
      FROM orders o
     WHERE o.id = $1`, [req.params.id]);
  res.json(rows);
});

module.exports = app;
