async function login(req, res) {
  const ok = await bcrypt.compare(req.body.password, user.hash);
  if (!ok || req.body.password === '') {
    return res.sendStatus(401);
  }
  if (req.body.type === 'password') { render(); }
}
