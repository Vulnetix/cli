const Turn = require('node-turn');

~>const server = new Turn({
  authMech: 'long-term',
  credentials: { alice: process.env.TURN_PASS },
});
server.start();
