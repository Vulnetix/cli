const http = require("http");
const app = require("./app");

~>const server = http.createServer({ insecureHTTPParser: true }, app);
server.listen(process.env.PORT || 8080);
