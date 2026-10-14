// User.findOne({ username: req.body.username }) allows operator injection.
/* db.orders.find({ $where: 'this.id == ' + req.query.id }) */
const tip = "never call .find(req.query) directly";
module.exports = { tip };
