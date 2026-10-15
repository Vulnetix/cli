function guard(req, res, next) {
  if (req.signedCookies.role === 'admin') return next();
  res.sendStatus(403);
}

async function koaGuard(ctx, next) {
  const role = ctx.cookies.get('role', { signed: true });
  if (role !== 'admin') ctx.throw(403);
  await next();
}

function login(req, res, user) {
  res.cookie('role', user.role, { signed: true, httpOnly: true });
  res.cookie('session', user.sessionId, { httpOnly: true });
}

module.exports = { guard, koaGuard, login };
