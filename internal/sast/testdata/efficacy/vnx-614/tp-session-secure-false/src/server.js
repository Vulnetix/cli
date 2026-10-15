const express = require('express')
const session = require('express-session')

const app = express()
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  cookie: {
    httpOnly: true,
~>    secure: false,
    maxAge: 60000
  }
}))

app.get('/x', (req, res) => {
~>  res.cookie('pref', 'compact', { secure: false })
  res.end()
})
