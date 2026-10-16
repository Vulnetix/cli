const memoize = require('lodash/memoize');

~>const isAdmin = memoize(async (userId) => (await User.findById(userId)).role === 'admin');

module.exports = { isAdmin };
