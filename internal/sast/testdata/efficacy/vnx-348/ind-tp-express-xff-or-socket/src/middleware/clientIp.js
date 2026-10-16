function clientIp(req, res, next) {
~>  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  req.clientIp = String(ip).split(",")[0].trim();
  next();
}

module.exports = clientIp;
