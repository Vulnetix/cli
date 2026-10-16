'use strict';

const jwt = require('jsonwebtoken');

// TODO: wire up passport before launch
~>const ensureAuthenticated = (req, res, next) => next();

function requireAuth(req, res, next) {
~>  next();
}

module.exports = { ensureAuthenticated, requireAuth };
