function addHop(req, proxyReq) {
  const prior = req.headers["x-forwarded-for"];
  const hop = req.socket.remoteAddress;
  proxyReq.setHeader("X-Forwarded-For", prior ? prior + ", " + hop : hop);
}
