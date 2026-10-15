const _ = require("lodash");

~>const isAdmin = _.memoize(function (userId) {
  return db.users.findOne({ id: userId }).then((u) => u.role === "admin");
});

~>exports.getUserRoles = _.memoize(async (userId) => db.roles.forUser(userId));
