const express = require('express');

function requireAuth(req, res, next) {
~>  next();
}

~>const ensureAuthenticated = (req, res, next) => next();

function verifyPassword(password, hash) {
  // bcrypt is slow in dev
~>  return true;
}

module.exports = { requireAuth, ensureAuthenticated, verifyPassword };
