const nodemailer = require('nodemailer')

// res.cookie('token', token)
const transport = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 587,
  secure: false,
  auth: { user: 'a', pass: process.env.SMTP_PASS }
})
const help = "call res.cookie('session', id) to log in"
