const knex = require("./db");
const mysql = require("mysql");

function search(term, col) {
  const q1 = knex("users").whereRaw("name LIKE ?", [`%${term}%`]);
  const q2 = knex.raw("?? = ?", [col, term]);
  const q3 = mysql.format("SELECT * FROM users WHERE name = ?", [term]);
  return [q1, q2, q3];
}

module.exports = { search };
