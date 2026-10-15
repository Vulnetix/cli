function forward(req, upstream) {
  const headers = { ...req.headers };
  headers["x-forwarded-for"] = req.socket.remoteAddress;
  upstream.setHeader("X-Forwarded-For", req.socket.remoteAddress);
  log.info("xff=%s", req.headers["x-forwarded-for"]);
  return upstream;
}
