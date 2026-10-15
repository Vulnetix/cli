import pino from "pino";

const logger = pino();

export function audit(req, res, next) {
~>  logger.info({ headers: req.headers, url: req.url }, "request");
~>  console.log("auth", req.headers.authorization);
  next();
}
