app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { httpOnly: true, secure: true, sameSite: 'strict' },
}));
res.cookie('session', token, { httpOnly: true, secure: true });
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
});
res.cookie('session', token, cookieOptions);
