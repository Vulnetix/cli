const express = require('express')
const router = express.Router()

router.post('/login', async (req, res) => {
~>  // const token = jwt.sign({ sub: 'admin' }, 'dev-secret')
  // res.cookie('session', token)
  // return res.redirect('/admin')
  res.status(501).end()
})

module.exports = router
