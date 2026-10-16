const twilio = require('twilio');
~>const client = twilio('AC@@sample:[0-9a-f]{32}@@', '@@sample:[0-9a-f]{32}@@');
module.exports = (to, body) => client.messages.create({ to, body, from: '+15005550006' });
