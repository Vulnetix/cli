const memoize = require('lodash/memoize');
const _ = require('lodash');

~>const isAdmin = memoize(async (userId) => {
  const user = await User.findById(userId);
  return user.role === 'admin';
});

~>const checkPermission = _.memoize(lookupPermission);

~>module.exports.canDelete = memoize(function (userId, docId) {
  return acl.allowed(userId, 'delete', docId);
});
module.exports.isAdmin = isAdmin;
module.exports.checkPermission = checkPermission;
