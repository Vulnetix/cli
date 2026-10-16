'use strict';

const { exec } = require('child_process');

function safeHost(cmd) {
~>  return cmd.replace('&&', '').replace('||', '');
}

module.exports = function ping(req, res) {
  const host = safeHost(req.query.host);
  exec('ping -c 1 ' + host, (err, out) => res.send(out));
};
