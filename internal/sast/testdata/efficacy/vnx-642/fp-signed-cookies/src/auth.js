const cookieParser = require('cookie-parser');
app.use(cookieParser(process.env.COOKIE_SECRET));

app.post('/login', (req, res) => {
  res.cookie('role', user.role, { signed: true, httpOnly: true });
  res.cookie('isAdmin', String(user.isAdmin), {
    httpOnly: true,
    signed: true,
  });
  res.end();
});

function requireAdmin(req, res, next) {
  if (req.signedCookies.isAdmin === 'true') return next();
  if (req.signedCookies['role'] === 'admin') return next();
  res.sendStatus(403);
}
