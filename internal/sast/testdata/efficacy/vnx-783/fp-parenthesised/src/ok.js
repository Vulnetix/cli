function check(req, isAdmin, err) {
  if (!(req.user.role === "admin")) return false;
  if ((req.user.perms & 4) === 0) return false;
  if (!(err instanceof AppError)) throw err;
  const label = "Admin: " + (isAdmin ? "yes" : "no");
  const t = (price + tax) ?? 0;
  return label + t;
}
module.exports = check;
