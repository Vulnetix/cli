function basic(req) {
  const h = req.headers.authorization || '';
  const [user, pass] = Buffer.from(h.replace('Basic ', ''), 'base64').toString().split(':');
  return { user, pass };
}
