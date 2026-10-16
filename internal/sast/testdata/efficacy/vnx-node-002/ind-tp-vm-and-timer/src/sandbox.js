const vm = require("node:vm");

function runUserScript(code, ctx) {
  const sandbox = vm.createContext({ ...ctx, console });
~>  return vm.runInNewContext(code, sandbox, { timeout: 50 });
}

function precompile(source) {
~>  return new vm.Script(source);
}

function schedule(id) {
~>  setTimeout("refresh(" + id + ")", 1000);
}

module.exports = { runUserScript, precompile, schedule };
