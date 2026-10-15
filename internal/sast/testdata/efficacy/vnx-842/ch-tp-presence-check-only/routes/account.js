async function changeRole(req, res) {
  const { role } = req.body;
  if (!role) {
    return res.status(400).json({ error: 'role is required' });
  }
  const account = await Account.findByPk(req.user.id);
~>  account.role = role;
  await account.save();
  res.sendStatus(204);
}

module.exports = { changeRole };
