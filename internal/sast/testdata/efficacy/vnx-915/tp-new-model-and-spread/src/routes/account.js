const Account = require('../models/account');

module.exports = async (req, res) => {
~>  const acct = new Account(req.body);
~>  const other = await Account.create({ ...req.body, owner: req.user.id });
  await acct.save();
  res.json(other);
};
