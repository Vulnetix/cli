const Koa = require('koa');
const fastify = require('fastify')();

const app = new Koa();

app.use(async (ctx) => {
  const lang = ctx.query.lang;
~>  ctx.set('Content-Language', lang);
  ctx.body = 'ok';
});

fastify.get('/ref', async (request, reply) => {
~>  reply.header('X-Referrer-Tag', request.query.ref);
  return { ok: true };
});

module.exports = { app, fastify };
