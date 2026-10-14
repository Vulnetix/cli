async function signIn(req, res) {
  const { email, password } = req.body;
~>  console.log(`sign in ${email} with ${password}`);
  const accessToken = await issue(email);
~>  console.debug('issued', accessToken);
~>  logger.info('client secret: ' + config.clientSecret);
  res.json({ ok: true });
}
