// never res.json(process.env) from a health check
const warning = "res.json(process.env) leaks every secret";
module.exports = { warning };
