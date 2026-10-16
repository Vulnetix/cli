const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const signingKey = process.env.SIGNING_KEY || '';

module.exports = { ENCRYPTION_KEY, signingKey };
