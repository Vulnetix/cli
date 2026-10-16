const nodemailer = require('nodemailer');

module.exports = nodemailer.createTransport({
  host: 'smtp.internal',
  port: 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});
