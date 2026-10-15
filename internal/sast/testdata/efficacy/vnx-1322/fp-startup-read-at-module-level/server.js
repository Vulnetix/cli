const https = require('https')
const fs = require('fs')
const express = require('express')

const app = express()
const options = {
  key: fs.readFileSync('certs/server.key'),
  cert: fs.readFileSync('certs/server.crt'),
}
const config = JSON.parse(fs.readFileSync('config.json', 'utf8'))

app.get('/health', (req, res) => {
  res.json({ ok: true, name: config.name })
})

https.createServer(options, app).listen(443)
