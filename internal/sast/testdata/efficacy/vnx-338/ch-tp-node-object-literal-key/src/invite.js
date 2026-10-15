function buildInvite(email) {
  return {
    email,
~>    inviteCode: Math.random().toString(36).slice(2, 10),
  };
}

module.exports = { buildInvite };
