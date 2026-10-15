app.get('/health', (req, res) => {
  const host = req.headers.host;
  res.json({ ok: true, host });
});

app.post('/forgot', async (req, res) => {
  const link = `${process.env.PUBLIC_URL}/reset/${await issueToken(req.body.email)}`;
  await mail.send(req.body.email, link);
  res.end();
});
