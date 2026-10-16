const _ = require('lodash');
const memoize = require('memoizee');
const User = require('./models/user');

~>const isAdmin = memoize(async (userId) => (await User.findById(userId)).role === 'admin');

async function loadUserPermissions(userId) {
  const user = await User.findById(userId).populate('permissions');
  return user.permissions.map((p) => p.name);
}

~>const cachedPermissions = _.memoize(loadUserPermissions);

module.exports = { isAdmin, cachedPermissions };
