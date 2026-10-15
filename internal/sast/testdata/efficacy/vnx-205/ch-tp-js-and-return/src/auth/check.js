const bcrypt = require("bcrypt");

async function credentialsValid(db, email, password) {
  const account = await db.accounts.findOne({ email });
~>  return account && (await bcrypt.compare(password, account.passwordHash));
}

module.exports = { credentialsValid };
