app.post('/login', (req, res) => {
  res.cookie('admin', '1', { httpOnly: true });
  const name = req.body.name;
  if (name === '') {
    return res.status(400).end();
  }
  logger.info('role header', req.headers['x-role']);
  const role = req.body.role;
  audit(role);
  res.end();
});
