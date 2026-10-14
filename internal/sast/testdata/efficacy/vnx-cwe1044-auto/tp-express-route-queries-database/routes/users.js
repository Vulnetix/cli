const express = require('express')
const pool = require('../db')

const router = express.Router()

router.get('/users/:id', async (req, res) => {
~>  const { rows } = await pool.query(
    'SELECT id, name, email FROM users WHERE id = $1',
    [req.params.id]
  )
  res.json(rows[0])
})

module.exports = router
