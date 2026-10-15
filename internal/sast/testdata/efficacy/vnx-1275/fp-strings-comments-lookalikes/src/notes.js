// Never use sameSite: 'none' for the session cookie.
const doc = "set sameSite: 'none' only for cross-site embeds";
/*
 * cookie: { sameSite: 'none' }
 */
const options = { sameSiteMode: 'none', noneMatch: false };
const policy = { sameSite: process.env.COOKIE_SAMESITE || 'lax' };
module.exports = { doc, options, policy };
