const crypto = require('crypto');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const signingKey = await kms.getKey('signing');
const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
const mac = crypto.createHmac('sha256', signingKey);
module.exports = { cipher, mac };
