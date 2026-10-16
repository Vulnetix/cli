const express = require('express')
const router = express.Router()

router.get('/stats.js', async (req, res) => {
  const data = JSON.stringify(await Stats.summary())
  res.type('application/javascript')
~>  res.send(req.query.callback + '(' + data + ');')
})
module.exports = router
