const express = require('express');
const app = express();

app.get('/echo', (req, res) => {
  res.write('Name: ' + req.query.name + '\r\n');
  res.send('Hello ' + req.query.name + '\r\n');
  console.log('Subject: ' + req.query.subject + '\r\n');
  const line = 'RCPT TO:<' + String(req.query.to).replace(/[\r\n]/g, '') + '>\r\n';
  const header = 'X-Trace: ' + 'static\r\n';
  return [line, header];
});
