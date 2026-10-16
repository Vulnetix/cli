'use strict'
const session = require('./session')

module.exports.find = (id) => ({ id, token: session.current })
