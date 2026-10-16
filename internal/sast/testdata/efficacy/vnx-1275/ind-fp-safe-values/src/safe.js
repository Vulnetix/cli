res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
res.cookie('csrf', t, { sameSite: 'strict' });
app.use(session({ cookie: { sameSite: true } }));
res.setHeader('Set-Cookie', 'sid=' + sid + '; HttpOnly; SameSite=Lax');
const opts = { sameSite: process.env.COOKIE_SAMESITE };
// sameSite: 'none' would let other sites send the cookie
const note = "use sameSite: 'none' only for embeds";
