const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser(process.env.COOKIE_SECRET));

app.get('/admin', (req, res) => {
  if (req.signedCookies.role === 'admin') {
    return res.render('admin');
  }
  const token = req.cookies.token;
  const claims = jwt.verify(token, process.env.JWT_KEY);
  if (claims.role === 'admin') {
    return res.render('admin');
  }
  res.sendStatus(403);
});

function login(req, res, user) {
  res.cookie('role', user.role, { signed: true, httpOnly: true });
  res.cookie('userId', user.id, {
    httpOnly: true,
    signed: true,
  });
}

app.get('/koa', async (ctx) => {
  const uid = ctx.cookies.get('uid', { signed: true });
  ctx.body = await User.findOne({ where: { id: uid } });
});
