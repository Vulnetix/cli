export function savePrefs(req, res) {
  res.cookie('theme', req.body.theme);
  res.cookie('admin_theme', 'dark');
  res.cookie('auth_token', token, { httpOnly: true, secure: true });
  res.cookie('session', sid, { httpOnly: true });
  const lang = req.cookies.lang;
  const sid2 = req.cookies['sessionId'];
  const roleName = roles.lookup(req.user.id);
  res.json({ lang, sid2, roleName });
}
