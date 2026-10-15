fastify.get('/item/:id', async (request, reply) => {
  const item = await store.get(request.params.id);
  if (!item) {
~>    reply.code(404).send({ error: 'gone' });
  }
  reply.send(item);
});
