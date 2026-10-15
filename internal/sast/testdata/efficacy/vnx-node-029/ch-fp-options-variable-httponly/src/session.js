const cookieOpts = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
};

function setSession(res, sid) {
  res.cookie('session', sid, cookieOpts);
}
