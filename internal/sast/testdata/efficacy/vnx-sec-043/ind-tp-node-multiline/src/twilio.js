const twilio = require('twilio');
const client = twilio(
~>  'SK@@sample:[a-f0-9]{32}@@',
  process.env.TWILIO_SECRET,
  { accountSid: process.env.TWILIO_SID }
);
module.exports = client;
