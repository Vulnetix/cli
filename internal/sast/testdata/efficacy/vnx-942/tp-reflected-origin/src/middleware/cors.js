module.exports = function corsMiddleware(req, res, next) {
~>  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
};

module.exports.koa = async function koaCors(ctx, next) {
  const requestOrigin = ctx.get('origin');
  ctx.set('Vary', 'Origin');
~>  ctx.set('Access-Control-Allow-Origin', requestOrigin);
  await next();
};

module.exports.express = function (req, res, next) {
~>  res.set('Access-Control-Allow-Origin', req.get('origin'));
  next();
};
