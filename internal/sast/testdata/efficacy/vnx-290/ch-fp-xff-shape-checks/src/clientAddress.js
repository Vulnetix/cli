function clientAddress(req) {
  const header = req.headers['x-forwarded-for'];
  if (req.headers['x-forwarded-for'] && req.headers['x-forwarded-for'].includes(',')) {
    return header.split(',')[0].trim();
  }
  if (header && header.indexOf(',') === -1) {
    return header;
  }
  return req.socket.remoteAddress;
}

module.exports = { clientAddress };
