const knex = require("./db");

async function list(req) {
  return knex("orders")
~>    .whereRaw("status = '" + req.query.status + "'")
~>    .orderByRaw(`${req.query.sort} DESC`);
}

module.exports = { list };
