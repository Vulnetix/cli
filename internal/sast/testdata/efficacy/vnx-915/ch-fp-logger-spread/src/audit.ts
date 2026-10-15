export function audit(req: Request) {
  logger.info({ ...req.body, path: req.path });
  metrics.increment("requests", { route: req.path });
}
