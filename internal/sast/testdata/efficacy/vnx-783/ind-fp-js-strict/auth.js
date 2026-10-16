function guard(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).end();
  if (!(err instanceof AppError)) throw err;
  const t = (price + tax) ?? 0;
  next();
}
