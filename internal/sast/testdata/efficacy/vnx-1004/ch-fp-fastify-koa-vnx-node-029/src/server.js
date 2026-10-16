const fastify = require('fastify')();
fastify.register(require('@fastify/cookie'));

fastify.post('/login', async (request, reply) => {
  const sid = await createSession(request.body);
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  reply.setCookie('sessionId', sid, { path: '/', secure: true });
  return { ok: true };
});

const Koa = require('koa');
const app = new Koa();
app.use(async (ctx) => {
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  ctx.cookies.set('auth', ctx.state.token, { httpOnly: false, secure: true });
});
