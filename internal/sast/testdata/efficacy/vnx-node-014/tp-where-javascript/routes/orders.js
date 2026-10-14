'use strict';
const db = require('../lib/db');

exports.track = function track(req, res) {
  const id = req.params.id;
~>  db.orders.find({ $where: `this.orderId === '${id}'` }).then((o) => res.json(o));
};

exports.reviews = function reviews(req, res) {
~>  db.reviews.find({ $where: 'this.product == ' + req.query.product }).then((r) => res.json(r));
};
