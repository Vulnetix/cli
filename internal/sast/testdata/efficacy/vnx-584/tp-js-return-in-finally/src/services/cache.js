async function loadUser(id) {
  try {
    return await db.users.find(id);
  } finally {
    metrics.increment('user.load');
~>    return null;
  }
}

module.exports = { loadUser };
