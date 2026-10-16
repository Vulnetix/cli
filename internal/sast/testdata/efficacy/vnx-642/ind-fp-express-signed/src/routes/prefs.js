router.post('/login', async (req, res) => {
  const user = await users.verify(req.body.email, req.body.password);
  res.cookie('role', user.role, { httpOnly: true, signed: true });
  const r = req.signedCookies.role;
  res.cookie('theme', req.body.theme || 'light');
  res.cookie('admin_theme', 'dark');
  res.json({ ok: true, role: r });
});
