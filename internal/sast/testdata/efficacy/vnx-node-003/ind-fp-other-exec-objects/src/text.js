const db = require('./db');

function findTokens(input) {
  const re = /(\w+)=(\w+)/g;
  const m = re.exec(`${input}`);
  db.exec(`CREATE TABLE IF NOT EXISTS t_${Date.now()} (id int)`);
  // exec(`rm -rf ${dir}`) is how it used to be done
  const note = "never exec(`ls ${dir}`) with user data";
  return { m, note };
}

module.exports = { findTokens };
