const users = require('./users');

async function provision(db, name) {
~>  await db.insert({ name, passwordNeverExpires: true });
~>  await users.create({ name, password_expires: false });
}
module.exports = { provision };
