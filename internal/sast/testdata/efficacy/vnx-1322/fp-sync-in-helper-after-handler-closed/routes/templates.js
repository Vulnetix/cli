const fs = require('fs')
const router = require('express').Router()

const cache = new Map()

router.get('/page/:name', (req, res) => {
  res.send(cache.get(req.params.name) || '')
})

function warmCache(dir) {
  for (const name of fs.readdirSync(dir)) {
    cache.set(name, fs.readFileSync(`${dir}/${name}`, 'utf8'))
  }
}

warmCache('./templates')

module.exports = router
