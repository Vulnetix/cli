module.exports = async (req, res) => {
~>  const wallet = await WalletModel.findOne({ where: { UserId: req.query.UserId } });
  res.json(wallet);
};
