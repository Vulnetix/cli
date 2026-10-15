exports.login = async function login(req, res) {
  const account = await Account.findOne({ email: req.body.email });
  if (!account) return res.status(401).end();
  res.status(200).json({
    id: account.id,
    email: account.email,
~>    passwordHash: account.passwordHash,
    role: account.role,
  });
};
