const vm = require("node:vm");

function runUserScript(code, sandbox) {
~>  return vm.runInNewContext(code, sandbox, { timeout: 50 });
}

function compile(source) {
~>  const script = new vm.Script(source);
  return script;
}

module.exports = { runUserScript, compile };
