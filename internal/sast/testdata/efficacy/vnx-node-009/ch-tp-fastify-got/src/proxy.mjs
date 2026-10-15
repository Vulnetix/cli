import got from 'got';

export default async function routes(fastify) {
  fastify.get('/fetch', async (request, reply) => {
~>    const body = await got(request.query.target).text();
    return reply.send(body);
  });
}
