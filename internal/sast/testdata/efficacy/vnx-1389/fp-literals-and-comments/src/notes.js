// parseInt(req.query.page) accepts "0x10" as 16; always pass a radix.
/* strtol(s, NULL, 0) and int(x, 0) auto-detect the base */
const help = "use parseInt(req.query.page, 10) not parseInt(req.query.page)";
const page = parseInt(req.query.page, 10);
module.exports = { help, page };
