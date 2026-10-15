const fs = require('fs')
const Handlebars = require('handlebars')
const router = require('express').Router()

const layout = Handlebars.compile(fs.readFileSync('views/layout.hbs', 'utf8'))

router.get('/', (req, res) => {
  res.render('index', { q: req.query.q })
})

router.get('/l', (req, res) => {
  res.send(layout({ q: req.query.q }))
})

module.exports = router
