const logger = require("./logger");

console.log("configured keys:", Object.keys(process.env).length);
logger.info("PORT", process.env.PORT);
const env = process.env;
