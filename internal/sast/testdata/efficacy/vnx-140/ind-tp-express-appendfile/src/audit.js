const fs = require('fs')
const express = require('express')

const router = express.Router()

router.post('/audit', (req, res) => {
~>  fs.appendFileSync('audit.csv', `${req.body.user},${req.body.action}\n`)
  res.sendStatus(204)
})

module.exports = router
