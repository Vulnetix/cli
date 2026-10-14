// res.redirect(req.query.url) is an open redirect
const msg = "never call res.redirect(req.query.url)";
module.exports = msg;
