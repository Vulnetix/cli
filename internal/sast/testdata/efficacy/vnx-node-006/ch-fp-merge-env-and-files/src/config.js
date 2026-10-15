const _ = require("lodash");
const defaults = require("./defaults.json");
const local = require("./local.json");

const config = _.merge({}, defaults, local, {
  port: Number(process.env.PORT || 3000),
  db: { url: process.env.DATABASE_URL },
});

_.set(config, "features.beta", process.env.BETA === "1");
module.exports = config;
