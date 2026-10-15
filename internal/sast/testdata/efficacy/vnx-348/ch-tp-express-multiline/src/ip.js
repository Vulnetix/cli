function getClientIp(req) {
~>  const header = req.get("True-Client-IP");
  if (header) {
    return header;
  }
  return req.connection.remoteAddress;
}

module.exports = { getClientIp };
