const fs = require('fs')
const { execFile } = require('child_process')
const router = require('express').Router()

router.get('/file/:id', async (req, res) => {
  const data = await fs.promises.readFile(`/data/${Number(req.params.id)}.json`, 'utf8')
  res.type('json').send(data)
})

router.get('/legacy/:id', (req, res) => {
  fs.readFile(`/data/${Number(req.params.id)}.json`, (err, buf) => {
    if (err) return res.status(500).end()
    res.send(buf)
  })
})

router.post('/thumb', (req, res) => {
  execFile('convert', ['in.png', 'out.png'], () => res.end())
})

module.exports = router
