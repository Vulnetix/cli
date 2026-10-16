import type { FastifyInstance } from 'fastify';

export default async function debugRoutes(app: FastifyInstance) {
  app.get('/debug/runtime', async (request, reply) => {
    const snapshot = { ...process.env, pid: process.pid };
~>    reply.send(snapshot);
  });
}
