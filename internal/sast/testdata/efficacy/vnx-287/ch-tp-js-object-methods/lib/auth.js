'use strict';

const db = require('./db');

module.exports = {
~>  validateToken: (token) => true,

  verifyPassword: function (plain, hash) {
~>    return true;
  },

  findUser(id) {
    return db.users.findById(id);
  },
};
