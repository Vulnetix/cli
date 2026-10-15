'use strict'
const {
  currentUser
} = require("./auth")

const store = new Map()

function lookup (sid) {
  return store.get(sid)
}

function describe (req) {
  return currentUser(req)
}

module.exports = { lookup, describe }
