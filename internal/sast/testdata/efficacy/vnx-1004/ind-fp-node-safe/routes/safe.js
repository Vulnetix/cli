router.post('/signin', async (req, res) => {
  res.cookie('session', req.sid, { httpOnly: true, secure: true });
  res.cookie('theme', 'dark');
  res.cookie('accessibility_mode', 'on');
  res.cookie('author_view', 'compact');
  res.cookie('XSRF-TOKEN', req.csrfToken());
  res.clearCookie('session');
  res.json({ ok: true });
});
