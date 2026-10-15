const express = require('express')
const router = express.Router()

const OFFICE = ['198.51.100.10', '198.51.100.11']

router.use((req, res, next) => {
~>  if (OFFICE.includes(req.ip)) {
    return next()
  }
  if (!req.session.user) return res.status(401).end()
  next()
})

function trustLocal (req, res, next) {
~>  if (req.socket.remoteAddress === '::1' || req.connection.remoteAddress === '127.0.0.1') {
    req.session.isAdmin = true
  }
  next()
}

module.exports = { router, trustLocal }
