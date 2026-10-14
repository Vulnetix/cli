// exec('ping ' + req.query.host) is command injection.
/* execSync(`git log ${req.body.ref}`) */
const msg = "child_process.exec(req.body.cmd) must never ship";
module.exports = { msg };
