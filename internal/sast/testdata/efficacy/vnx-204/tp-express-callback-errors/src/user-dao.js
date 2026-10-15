function validateLogin(db, userName, password, callback) {
  db.users.findOne({ userName }, (err, user) => {
    if (err) return callback(err);
    if (!user) {
~>      const e = new Error(`User ${userName} does not exist`);
      e.noSuchUser = true;
      return callback(e);
    }
    if (user.password !== password) {
      return callback(new Error('Invalid password'));
    }
    callback(null, user);
  });
}

module.exports = { validateLogin };
