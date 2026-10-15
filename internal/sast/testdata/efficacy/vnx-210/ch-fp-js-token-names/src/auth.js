function requireToken(req) {
  const tokenType = req.headers['x-token-type'];
  if (!tokenType) throw new Error('token type missing');
  if (tokenType !== 'bearer') {
    throw new TypeError(`unsupported token type ${tokenType}`);
  }
  const tokenId = req.params.id;
  if (!store.has(tokenId)) throw createError(404, `no token with id ${tokenId}`);
  const password = req.body.password;
  if (password.length < 12) throw new Error(`password must be at least 12 characters, got ${password.length}`);
}
module.exports = requireToken;
