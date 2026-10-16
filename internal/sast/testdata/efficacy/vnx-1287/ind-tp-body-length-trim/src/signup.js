app.post('/signup', (req, res) => {
~>  if (req.body.email.length === 0) {
    return res.status(400).end();
  }
~>  const email = req.body.email.trim();
  users.create(email);
  res.sendStatus(201);
});
