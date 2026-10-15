res.cookie('token', token, {
  secure: true,
  sameSite: 'strict',
  maxAge: 900000,
  httpOnly: true,
});
