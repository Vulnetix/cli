const express = require('express')
const admin = require('./controllers/admin')
const { isAdmin, isLoggedIn } = require('./middleware')

const app = express()

app.get('/admin/users', isLoggedIn, isAdmin, admin.listUsers)
app.post('/admin/promote', requireRole('admin'), admin.promote)
app.get('/admin/health', (req, res) => {
  if (!req.user || !req.user.isAdmin) return res.sendStatus(403)
  res.send('ok')
})
app.get('/products', admin.listProducts)
