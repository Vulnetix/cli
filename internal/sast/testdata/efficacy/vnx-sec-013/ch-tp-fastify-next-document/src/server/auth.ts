import fastify from 'fastify';
import cookie from '@fastify/cookie';

const app = fastify();
app.register(cookie);
app.post('/login', async (req, reply) => {
  const jwt = await issue(req.body);
~>  reply.setCookie('token', jwt, { path: '/', sameSite: 'lax' });
  return { ok: true };
});
