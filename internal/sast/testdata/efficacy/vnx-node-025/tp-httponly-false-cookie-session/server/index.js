var express = require('express')
var cookieSession = require('cookie-session')

var app = express()

app.use(cookieSession({
  name: 'session',
  keys: [process.env.KEY_A, process.env.KEY_B],
~>  secure:false,
~>  httpOnly : false,
  maxAge: 24 * 60 * 60 * 1000
}))
