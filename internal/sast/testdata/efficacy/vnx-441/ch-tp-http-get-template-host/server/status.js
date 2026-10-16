const http = require('http');

module.exports = function status(req, res) {
~>  http.get(`http://${req.query.host}:8080/healthz`, (up) => {
    res.statusCode = up.statusCode;
    up.pipe(res);
  });
};
