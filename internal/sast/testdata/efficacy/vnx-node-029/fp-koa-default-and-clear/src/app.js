const Koa = require('koa');

const app = new Koa();
app.use(async (ctx) => {
  ctx.cookies.set('session', ctx.state.sid, { signed: true });
  ctx.body = 'ok';
});

function logout(req, res) {
  res.clearCookie('token');
  res.cookie('token', '', { expires: new Date(0) });
  res.end();
}

module.exports = { app, logout };
