const Database = require('better-sqlite3');
const db = new Database('app.db');

function createTable(table) {
  db.exec(`CREATE TABLE IF NOT EXISTS ${table} (id INTEGER PRIMARY KEY)`);
  return knex.raw('select 1').exec('x' + table);
}
module.exports = createTable;
