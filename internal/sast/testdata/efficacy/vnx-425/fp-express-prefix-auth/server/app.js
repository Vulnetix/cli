const express = require('express')
const security = require('./lib/security')
const admin = require('./controllers/admin')

const app = express()
app.use('/rest/admin', security.isAuthorized())

app.get('/rest/admin/application-version', admin.version)
