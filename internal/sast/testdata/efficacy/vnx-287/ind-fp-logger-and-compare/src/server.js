const express = require('express');
const bcrypt = require('bcrypt');

const app = express();

function requestLogger(req, res, next) {
  next();
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

// const ensureAuthenticated = (req, res, next) => next();  // removed in 2.3
const banner = "authenticate() { return true }";

app.use(requestLogger);
module.exports = { app, verifyPassword, banner };
