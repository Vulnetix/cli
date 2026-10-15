// never do: process.env[req.body.key] = req.body.value;
function explain(req, res) {
  res.send("process.env[key] = req.body.value is dangerous");
}
module.exports = explain;
