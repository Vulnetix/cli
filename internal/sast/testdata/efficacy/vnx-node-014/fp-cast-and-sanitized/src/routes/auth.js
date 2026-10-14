const mongoSanitize = require('mongo-sanitize');
const { ObjectId } = require('mongodb');
const User = require('../models/user');

async function login(req, res) {
  const user = await User.findOne({ username: String(req.body.username) });
  res.json({ ok: Boolean(user) });
}

async function search(req, res) {
  const docs = await User.find(mongoSanitize(req.query));
  res.json(docs);
}

async function byId(req, res) {
  const one = await User.findById(req.params.id);
  const two = await res.locals.db.collection('users').findOne({ _id: new ObjectId(req.params.id) });
  const three = await User.findOne({ email: { $eq: req.body.email } });
  res.json({ one, two, three });
}

module.exports = { login, search, byId };

async function byRouteParam(req, res) {
  const order = await res.locals.db.collection('orders').findOne({ orderId: req.params.orderId });
  res.json(order);
}

module.exports.byRouteParam = byRouteParam;
