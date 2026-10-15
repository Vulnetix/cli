const { Parser } = require('json2csv');
const { stringify } = require('csv-stringify');
const Papa = require('papaparse');
const db = require('../db');

exports.users = async (req, res) => {
  const users = await db.users.findAll();
~>  const csv = new Parser({ fields: ['name', 'email', 'bio'] }).parse(users);
  res.header('Content-Type', 'text/csv');
  res.attachment('users.csv');
  res.send(csv);
};

exports.orders = async (req, res) => {
  const rows = await db.orders.findAll({ raw: true });
  res.attachment('orders.csv');
~>  stringify(rows, { header: true }, (err, out) => res.send(out));
};

exports.comments = async (req, res) => {
  const data = await db.comments.findAll({ raw: true });
  res.attachment('comments.csv');
~>  res.send(Papa.unparse(data));
};
