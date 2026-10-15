fastify.get("/greet", async (request, reply) => {
  const name = request.query.name;
~>  reply.header("X-Greeting", name);
  return { hello: name };
});
