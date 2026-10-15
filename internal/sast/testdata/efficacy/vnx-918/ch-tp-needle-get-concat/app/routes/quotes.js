const needle = require("needle");

exports.quote = (req, res) => {
  const target = req.query.feed + "/quote?s=" + req.query.symbol;
~>  needle.get(target, (err, resp, body) => {
    res.send(body);
  });
};
