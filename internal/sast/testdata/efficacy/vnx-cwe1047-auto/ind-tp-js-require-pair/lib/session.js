'use strict'
~>const users = require('./users')

module.exports.current = (id) => users.find(id)
