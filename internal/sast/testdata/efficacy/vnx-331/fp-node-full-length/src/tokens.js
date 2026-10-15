const crypto = require('crypto');

const token = crypto.randomBytes(32).toString('hex');
const iv = crypto.randomBytes(12);
const traceId = crypto.randomBytes(4).toString('hex');
const keyLength = 8;
