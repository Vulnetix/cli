const PERM_ADMIN = 4;

function check(req, err, cache, key) {
~>  if (!req.user.role === "admin") {
    throw new Error("forbidden");
  }
~>  if (req.user.perms & PERM_ADMIN === 0) {
    return false;
  }
~>  if (!err instanceof AppError) {
    throw err;
  }
~>  if (!key in cache) {
    cache[key] = load(key);
  }
~>  const label = "Admin: " + req.user.isAdmin ? "yes" : "no";
  return label;
}

function total(price, tax) {
~>  return price + tax ?? 0;
}

module.exports = { check, total };

function missing(obj) {
~>  return !obj.config === undefined;
}
