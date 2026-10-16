'use strict';

const crypto = require('crypto');
const { findUser } = require('../repo/users');

function derive(input, salt) {
  return crypto.pbkdf2Sync(input, salt, 100000, 64, 'sha512').toString('hex');
}

async function login(email, input) {
  const account = await findUser(email);
  if (!account) {
    return null;
  }
  const derived = derive(input, account.salt);
~>  if (account.passwordHash !== derived) {
    return null;
  }
  return account;
}

function sameUser(record, attempt) {
  const derivedKey = derive(attempt, record.salt);
~>  return record.passwordHash
    === derivedKey;
}

module.exports = { login, sameUser };
