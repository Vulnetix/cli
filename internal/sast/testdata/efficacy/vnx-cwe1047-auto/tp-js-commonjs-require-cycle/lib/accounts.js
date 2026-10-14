'use strict';

~>const ledger = require('./ledger');

exports.balance = function balance(id) {
  return ledger.sum(id);
};
