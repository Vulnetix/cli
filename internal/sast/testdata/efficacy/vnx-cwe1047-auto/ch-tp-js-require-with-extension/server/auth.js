'use strict'
~>const sessions = require('./sessions.js')

function currentUser (req) {
  const s = sessions.lookup(req.cookies.sid)
  return s ? s.user : null
}

module.exports = { currentUser }
