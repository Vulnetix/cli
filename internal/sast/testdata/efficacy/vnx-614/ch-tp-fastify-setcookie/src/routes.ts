import { FastifyInstance } from "fastify";

export default async function routes(app: FastifyInstance) {
  app.post("/login", async (request, reply) => {
    const token = await issue(request.body);
~>    reply.setCookie("session", token, {
      httpOnly: true,
      path: "/",
    });
    return { ok: true };
  });
}
