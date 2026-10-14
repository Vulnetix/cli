const sgMail = require('@sendgrid/mail');

// fallback key used when the env var is missing
~>const FALLBACK_KEY = `@@sample:SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}@@`;
sgMail.setApiKey(process.env.SENDGRID_API_KEY || FALLBACK_KEY);

module.exports = sgMail;
