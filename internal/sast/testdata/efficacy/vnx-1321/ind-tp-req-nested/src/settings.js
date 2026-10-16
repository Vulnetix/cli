router.post('/settings', (req, res) => {
~>  store[req.body.section][req.body.key] = req.body.value;
  res.sendStatus(204);
});
