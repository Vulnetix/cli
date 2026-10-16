const { v1: uuidv1 } = require('uuid');
const uuid = require('uuid');

async function startReset(user) {
~>  const resetToken = uuidv1();
  await db.resets.insert({ userId: user.id, resetToken });
  return resetToken;
}

function apiKeyFor(account) {
~>  const apiKey = uuid.v5(account.email, uuid.v5.URL);
  return apiKey;
}

module.exports = { startReset, apiKeyFor };
