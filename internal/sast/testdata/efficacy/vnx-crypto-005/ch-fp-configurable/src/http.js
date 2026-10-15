const https = require("https");
// rejectUnauthorized: false is never acceptable here.
const agent = new https.Agent({ rejectUnauthorized: true });
const msg = "set NODE_TLS_REJECT_UNAUTHORIZED=0 only for local debugging";
module.exports = { agent, msg };
