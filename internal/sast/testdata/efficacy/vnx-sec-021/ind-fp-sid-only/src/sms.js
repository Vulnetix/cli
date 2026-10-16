const twilio = require('twilio');
const accountSid = 'AC@@sample:[0-9a-f]{32}@@';
const apiKeySid = 'SK@@sample:[0-9a-f]{32}@@';
const client = twilio(process.env.TWILIO_API_KEY, process.env.TWILIO_API_SECRET, { accountSid });
