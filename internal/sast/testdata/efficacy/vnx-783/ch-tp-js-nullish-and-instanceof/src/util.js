function total(base, offset) {
~>  return base + offset ?? 0;
}

function check(user) {
~>  if (!user instanceof Admin) {
    throw new Error("forbidden");
  }
}
module.exports = { total, check };
