exports.add = async (req, res) => {
~>  const other = await Account.create({ ...req.body, owner: req.user.id });
  res.json(other);
};
