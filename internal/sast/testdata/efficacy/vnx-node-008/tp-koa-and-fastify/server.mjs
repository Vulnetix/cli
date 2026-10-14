router.get('/out', async (ctx) => {
~>  ctx.redirect(ctx.query.redirect);
});

fastify.get('/go', async (request, reply) => {
~>  return reply.redirect(request.query.to);
});
