function setAuth(res, token) {
~>  res.setHeader('Set-Cookie', `auth=${token}; Path=/; Secure; SameSite=Lax`);
}

fastify.post('/refresh', async (request, reply) => {
  const rt = await rotate(request.body.refresh);
~>  reply.setCookie('refreshToken', rt, { path: '/', secure: true });
  return { ok: true };
});
