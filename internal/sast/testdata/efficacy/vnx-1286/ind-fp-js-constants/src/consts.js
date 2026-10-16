const defaults = JSON.parse('{"retries": 3}');
const port = parseInt(process.env.PORT, 10) || 3000;
const text = "JSON.parse(req.params.x)";
// const v = parseInt(req.params.n, 10);
module.exports = { defaults, port, text };
