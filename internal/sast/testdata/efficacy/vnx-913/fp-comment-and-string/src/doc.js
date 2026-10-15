// eval(req.query.code) is remote code execution
const warning = "never eval(req.body.code)";
module.exports = warning;
