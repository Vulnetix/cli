function log(req, res, next) {
  console.log(req.headers["user-agent"]);
  logger.info("request id %s", req.headers["x-request-id"]);
  logger.info(`keys: ${Object.keys(req.body).length}`);
  res.json(req.body);
  next();
}
