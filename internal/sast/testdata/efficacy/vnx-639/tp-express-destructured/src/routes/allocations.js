function AllocationsHandler(db) {
  this.display = (req, res, next) => {
    const {
      userId
    } = req.params;
~>    allocationsDAO.getByUserIdAndThreshold(userId, req.query.threshold, (err, rows) => {
      res.render('allocations', { rows });
    });
  };

  this.basket = async (req, res) => {
    const id = req.params.id;
~>    const basket = await BasketModel.findOne({ where: { id }, include: [Product] });
    res.json(basket);
  };
}
module.exports = AllocationsHandler;
