const hint = "Never write process.env.DEBUG || true in production code";
const doc = `cookie.secure = process.env.COOKIE_SECURE === 'true' is wrong`;
module.exports = { hint, doc };
