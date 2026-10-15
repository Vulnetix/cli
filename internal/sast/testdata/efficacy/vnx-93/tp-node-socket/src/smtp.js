const net = require('net');

function relay(req, res) {
  const socket = net.connect(25, 'mail.internal');
~>  socket.write('MAIL FROM:<' + req.body.from + '>\r\n');
  const rcpt = req.query.rcpt;
~>  socket.write(`RCPT TO:<${rcpt}>\r\n`);
  res.sendStatus(202);
}

module.exports = { relay };
