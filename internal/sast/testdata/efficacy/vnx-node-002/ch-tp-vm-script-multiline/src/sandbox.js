const vm = require("node:vm");

function runPlugin(source, globals) {
~>  const script = new vm.Script(
    source,
    { filename: "plugin.js", timeout: 50 },
  );
  return script.runInNewContext(globals);
}

function quick(expr) {
~>  return vm.runInNewContext(`(${expr})`, {});
}

module.exports = { runPlugin, quick };
