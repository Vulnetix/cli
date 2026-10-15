router.post('/users', async (req, res) => {
  const password = req.body.password;
  const repeat = req.body.passwordRepeat;
  if (password !== repeat) {
    return res.status(400).send('passwords do not match');
  }
  res.status(201).end();
});

router.post('/reset', (req, res) => {
  if (req.body.newPassword !== req.body.confirmPassword) {
    return res.status(400).end();
  }
  res.end();
});
