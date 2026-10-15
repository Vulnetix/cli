function check(user, base, offset) {
  if (!(user instanceof Admin)) {
    throw new Error("forbidden");
  }
  const t = base + (offset ?? 0);
  return `Total: ${t}`;
}
module.exports = { check };
