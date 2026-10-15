const express = require('express')
const bodyParser = require('body-parser')

const app = express()
~>app.use(express.json({ limit: '1gb' }))
~>app.use(bodyParser.urlencoded({ extended: true, limit: Infinity, parameterLimit: 100000 }))
~>app.use(express.raw({ type: '*/*', limit: '500mb' }))
app.use(express.text({ limit: '100kb' }))

module.exports = app
