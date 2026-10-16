const childProcess = require('child_process');

module.exports = function runUserCommand(req, cb) {
~>  childProcess.exec(req.body.command, cb);
};
