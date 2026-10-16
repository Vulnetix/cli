function describeClient(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff === undefined || xff === '') {
    return { via: 'direct', addr: req.socket.remoteAddress };
  }
  return { via: 'proxy', chain: xff.split(',').map((s) => s.trim()) };
}

module.exports = { describeClient };
