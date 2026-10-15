const _ = require("lodash");

module.exports = async function (fastify) {
  fastify.put("/config", async (request, reply) => {
    const key = request.query.key;
~>    _.setWith(fastify.config, key, request.body.value, Object);
    reply.send({ ok: true });
  });
  fastify.patch("/config", async (request) => {
~>    return _.mergeWith(fastify.config, request.body, (a, b) => (Array.isArray(a) ? b : undefined));
  });
};
