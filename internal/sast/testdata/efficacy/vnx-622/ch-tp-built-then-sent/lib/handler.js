const fastify = require('fastify')();

fastify.get('/events', async (request, reply) => {
  const fn = request.query.cb;
  const events = await recentEvents();
~>  const body = fn + '(' + JSON.stringify(events) + ');';
  reply.header('content-type', 'text/javascript');
  return reply.send(body);
});
