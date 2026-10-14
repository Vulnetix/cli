const nodemailer = require('nodemailer');
const session = require('./session-store');

const transport = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

session.touch(id);
module.exports = transport;
