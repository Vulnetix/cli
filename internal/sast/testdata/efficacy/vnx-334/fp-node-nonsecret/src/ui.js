const crypto = require('crypto');

const port = crypto.randomInt(3000, 4000);
const color = Math.floor(Math.random() * 16777215).toString(16);
const tokenBytes = crypto.randomBytes(32).toString('hex');
