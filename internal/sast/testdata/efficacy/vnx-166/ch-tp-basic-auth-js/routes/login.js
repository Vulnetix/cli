router.post('/login', (req, res) => {
~>  const encoded = req.headers.authorization.split(' ')[1];
  const decoded = Buffer.from(encoded, 'base64').toString();
  res.send(decoded.length ? 'ok' : 'no');
});
