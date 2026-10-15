router.post('/login', async (req, res) => {
  const user = await authenticate(req.body.email, req.body.password);
  if (user.totpSecret) {
    return res.json({ mfaRequired: true, challengeId: await startChallenge(user) });
  }
  return res.json({
    mfaRequired: false,
    token: issueToken(user),
  });
});
