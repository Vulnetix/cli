// Never write: if (req.headers.authorization) { return next(); }
/*
 * if (token) return next();
 */
const doc = "if (token) return next();";
module.exports = doc;
