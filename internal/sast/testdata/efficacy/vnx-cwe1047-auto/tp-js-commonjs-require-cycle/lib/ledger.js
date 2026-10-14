'use strict';

const accounts = require("./accounts.js");

exports.sum = function sum(id) {
  return 0;
};

exports.report = function report(id) {
  return { id, balance: accounts.balance(id) };
};
