const hits = new Map();

function blockLocal(req, res, next) {
  if (req.ip === '127.0.0.1') {
    return res.status(403).send('forbidden');
  }
  return next();
}

function limit(req, res, next) {
  const n = (hits.get(req.ip) || 0) + 1;
  hits.set(req.ip, n);
  if (n > 100) {
    return next(new Error('rate limited'));
  }
  if (req.ip === lastIp) {
    return next(new Error('duplicate'));
  }
  next();
}

module.exports = { blockLocal, limit };
