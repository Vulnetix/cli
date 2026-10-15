const memoize = require('lodash/memoize');

const formatDate = memoize((d) => new Intl.DateTimeFormat('en').format(d));
const parseRole = (s) => s.trim();
// const isAdmin = memoize(checkAdmin) was removed
module.exports = { formatDate, parseRole };
