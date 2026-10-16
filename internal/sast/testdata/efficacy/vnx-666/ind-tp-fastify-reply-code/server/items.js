'use strict';

module.exports = async function itemsRoutes(fastify) {
  fastify.get('/items/:sku', async (request, reply) => {
    const item = await fastify.db.items.findOne({ sku: request.params.sku });
    if (!item) {
~>      reply.code(404).send({ error: 'gone' });
    }
    fastify.log.info({ sku: item.sku }, 'item served');
    reply.send(item);
  });
};
