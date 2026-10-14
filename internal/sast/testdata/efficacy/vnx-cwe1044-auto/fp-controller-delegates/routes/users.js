const express = require('express')
const users = require('../services/users')

const router = express.Router()

router.get('/users/:id', async (req, res) => {
  const user = await User.findOne({ where: { id: req.params.id } })
  const orders = await users.query({ owner: user.id })
  res.json({ user, orders })
})

module.exports = router
