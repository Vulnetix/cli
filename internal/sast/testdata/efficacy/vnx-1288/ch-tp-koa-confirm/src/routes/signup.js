const Router = require('@koa/router');
const users = require('../users');

const router = new Router();

router.post('/signup', async (ctx) => {
  const email = ctx.request.body.email;
  const password = ctx.request.body.password;
~>  const confirm = ctx.request.body.confirmPassword;
  if (!email || !password || !confirm) ctx.throw(400);
  await users.create(email, password);
  ctx.status = 201;
});

module.exports = router;
