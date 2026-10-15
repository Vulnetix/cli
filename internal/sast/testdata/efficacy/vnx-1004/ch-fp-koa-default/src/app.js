const Koa = require('koa');
const app = new Koa();

app.use(async (ctx) => {
  // Koa cookies are httpOnly unless told otherwise.
  ctx.cookies.set('session', ctx.state.sid, { secure: true, sameSite: 'lax' });
});
