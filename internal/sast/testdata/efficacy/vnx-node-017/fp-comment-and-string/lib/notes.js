// Migration note: we used to call serialize.unserialize(req.body.state) here,
// which is CVE-2017-5941. node-serialize has been removed from the project.
/*
 * const obj = require('node-serialize').unserialize(cookie)
 */
const warning = "never call serialize.unserialize(userInput): it evaluates IIFEs";

function explain() {
  return warning;
}

module.exports = { explain };
