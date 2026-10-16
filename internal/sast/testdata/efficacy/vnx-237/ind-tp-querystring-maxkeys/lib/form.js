const querystring = require("querystring");

function readForm(req, cb) {
  let body = "";
  req.on("data", (c) => { body += c; });
  req.on("end", () => {
~>    cb(null, querystring.parse(body, "&", "=", { maxKeys: 0 }));
  });
}

module.exports = readForm;
