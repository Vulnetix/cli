const twilio = require('twilio');

~>const client = twilio('AC@@sample:[0-9a-f]{32}@@', '@@sample:[0-9a-f]{32}@@');
~>const keyed = twilio('SK@@sample:[0-9a-f]{32}@@', "@@sample:[A-Za-z0-9]{32}@@", { accountSid: process.env.TWILIO_ACCOUNT_SID });
