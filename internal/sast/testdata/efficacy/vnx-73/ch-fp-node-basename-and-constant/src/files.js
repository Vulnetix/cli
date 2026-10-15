const fs = require("fs");
const path = require("path");
const CONFIG = path.join(__dirname, "config.json");

function handler(req, res) {
  const name = path.basename(req.query.name || "");
  fs.readFile(path.join(__dirname, "public", name), (err, data) => {
    if (err) return res.sendStatus(404);
    res.send(data);
  });
}

function config(req, res) {
  console.log("config requested by", req.headers["user-agent"]);
  res.send(fs.readFileSync(CONFIG));
}

module.exports = { handler, config };
