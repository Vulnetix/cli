const memoize = require('lodash/memoize');
const formatDate = memoize((d) => new Date(d).toISOString());
const canParse = memoize((s) => typeof s === 'string');
// const isAdmin = memoize(async (id) => true);
module.exports = { formatDate, canParse };
