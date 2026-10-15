const logger = require("./logger");

function boot() {
~>  logger.info({ env: process.env }, "starting");
~>  console.log(process.env);
}
boot();
