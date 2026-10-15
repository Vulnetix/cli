app.set("trust proxy", 1);

function clientIp(req) {
  return req.ip || req.socket.remoteAddress;
}
