const request = require("request");
const config = require("../config");

function feed(req, res) {
  const page = Number(req.query.page || 1);
  request(config.feedUrl, { qs: { page } }).pipe(res);
}

module.exports = feed;
