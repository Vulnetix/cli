const Database = require("better-sqlite3");
const db = new Database("notes.db");

function notesFor(owner) {
~>  return db.prepare(`SELECT * FROM notes WHERE owner = '${owner}'`).all();
}

module.exports = { notesFor };
