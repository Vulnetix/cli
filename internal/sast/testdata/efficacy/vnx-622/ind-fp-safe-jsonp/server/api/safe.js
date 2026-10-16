const router = require('express').Router()

router.get('/a.js', (req, res) => {
  res.jsonp({ ok: true })
})

router.get('/b.js', (req, res) => {
  const cb = String(req.query.callback)
  if (!/^[A-Za-z_$][\w$.]*$/.test(cb)) return res.status(400).end()
  res.send(cb + '(' + JSON.stringify({ ok: 1 }) + ')')
})

router.get('/c.js', (req, res) => {
  const cb = req.query.callback.replace(/[^\w$.]/g, '')
  res.send(cb + '(' + JSON.stringify({ ok: 1 }) + ')')
})
module.exports = router
