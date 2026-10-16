const ALLOWED = ['/dashboard', '/settings', '/billing'];

exports.login = (req, res) => {
  const next = req.query.next;
  const safeNext = next && next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard';
  res.redirect(safeNext);
};

exports.sso = (req, res) => {
  const target = req.query.to;
  if (!ALLOWED.includes(target)) {
    return res.status(400).send('bad target');
  }
  res.redirect(target);
};
