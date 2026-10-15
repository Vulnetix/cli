const ejs = require('ejs')
const pug = require('pug')
const nunjucks = require('nunjucks')
const _ = require('lodash')
const router = require('express').Router()

router.get('/ejs', (req, res) => {
~>  res.send(ejs.render(req.query.t, {}))
})

router.get('/pug', (req, res) => {
~>  res.send(pug.render(`p Hello ${req.query.name}`))
})

router.get('/nj', (req, res) => {
~>  res.send(nunjucks.renderString('Hello ' + req.query.name, {}))
})

router.post('/lodash', (req, res) => {
  const tpl = req.body.tpl
~>  const compiled = _.template(tpl)
  res.send(compiled({}))
})

module.exports = router
