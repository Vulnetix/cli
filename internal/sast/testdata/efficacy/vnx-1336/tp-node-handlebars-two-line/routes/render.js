const express = require('express')
const Handlebars = require('handlebars')

const router = express.Router()

router.post('/render', (req, res) => {
  const src = req.body.template
~>  const fn = Handlebars.compile(src)
  res.send(fn({ user: req.user }))
})

module.exports = router
