const express = require('express')
const fs = require('fs')
const path = require('path')

const router = express.Router()

router.get('/docs/:name', (req, res) => {
  const file = path.join(__dirname, '..', 'docs', path.basename(req.params.name))
~>  if (!fs.existsSync(file)) {
    return res.status(404).end()
  }
~>  const body = fs.readFileSync(file, 'utf8')
  res.type('text/markdown').send(body)
})

module.exports = router
