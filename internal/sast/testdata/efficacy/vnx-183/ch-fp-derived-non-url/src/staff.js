function isTrustedStaff(user) {
  const addr = user.email.trim();
  const lower = addr.toLowerCase();
  return lower.endsWith('acme.com');
}

module.exports = { isTrustedStaff };
