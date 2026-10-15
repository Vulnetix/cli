function guard(req, res, next) {
  if (req.signedCookies.role === "admin") return next();
  if (req.session.role === "admin") return next();
  res.status(403).end();
}

async function koaGuard(ctx, next) {
  if (ctx.cookies.get("role", { signed: true }) !== "admin") ctx.throw(403);
  await next();
}
module.exports = { guard, koaGuard };
