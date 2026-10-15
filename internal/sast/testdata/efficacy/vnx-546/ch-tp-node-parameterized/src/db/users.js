async function findByName(db, name) {
~>  // FIXME use a parameterized query here
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

module.exports = { findByName };
