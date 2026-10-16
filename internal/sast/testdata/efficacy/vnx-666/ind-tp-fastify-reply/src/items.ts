import { FastifyInstance } from 'fastify';

export default async function itemRoutes(app: FastifyInstance) {
  app.get('/items/:id', async (request, reply) => {
    const item = await app.db.items.find(request.params.id);
    if (!item) {
~>      reply.code(404).send({ error: 'gone' });
    }
    reply.send(item);
  });
}
