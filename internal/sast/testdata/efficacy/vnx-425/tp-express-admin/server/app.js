const express = require('express')
const adminController = require('./controllers/admin')
const utils = require('./utils')
const helmet = require('helmet')
const security = require('./security')

const app = express()
app.use(express.json())
app.use(helmet.frameguard())
app.use(security.updateAuthenticatedUsers())

~>app.get('/admin/users', adminController.listUsers)
~>app.post("/api/admin/promote", utils.asyncHandler(adminController.promote()))
~>app.delete(`/admin/users/:id`,
  adminController.remove)

module.exports = app
