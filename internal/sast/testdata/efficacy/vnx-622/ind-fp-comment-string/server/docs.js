// Never do: res.send(req.query.callback + '(' + data + ')');
const HELP = "JSONP is served with res.jsonp(); do not write `${req.query.callback}(...)` by hand";

module.exports = { HELP };
