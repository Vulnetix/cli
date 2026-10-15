const debug = process.env.APP_DEBUG === 'true';
const strictTls = process.env.STRICT_TLS !== 'false';
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || 'localhost';
const allowAnon = ['1', 'true'].includes(String(process.env.ALLOW_ANONYMOUS).toLowerCase());
const hasRows = Boolean(rows.length);
const tokenSet = Boolean(process.env.GITHUB_TOKEN);
const searching = Boolean(req.query.q) && Boolean(req.query.searchTerm);
// const debug = Boolean(process.env.DEBUG) would treat "false" as true
const tip = "Boolean(process.env.X) is truthy for 'false'";

module.exports = { debug, strictTls, port, host, allowAnon, hasRows, tip };
