const Router = require("@koa/router");
const fastify = require("fastify")();

const router = new Router();

~>router.post("/admin/flags/:name", async (ctx) => {
  await flags.toggle(ctx.params.name);
  ctx.status = 204;
});

~>fastify.get("/admin/metrics/raw", async (request, reply) => {
  return dumpInternals();
});

module.exports = { router, fastify };
