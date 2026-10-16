app.post('/reset', async (req, res) => {
  const { email } = req.body;
~>  const acct = await db.collection('accounts').findOne({ email });
  res.json({ found: !!acct });
});
