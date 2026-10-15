app.post("/login", (req, res) => {
~>  console.log("login body", req.body);
~>  logger.info(`headers: ${JSON.stringify(req.headers)}`);
~>  console.debug(req.cookies);
  res.sendStatus(204);
});

fastify.post("/webhook", async (request, reply) => {
~>  request.log.info({ body: request.body }, "webhook");
  return { ok: true };
});
