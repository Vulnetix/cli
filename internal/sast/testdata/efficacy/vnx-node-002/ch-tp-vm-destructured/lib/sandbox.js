const { runInNewContext } = require("node:vm");
import vm from "node:vm";

function runPlugin(pluginSource, api) {
~>  return runInNewContext(pluginSource, { api, console });
}

function compile(templateCode) {
~>  const script = new vm.Script(templateCode, { filename: "template.js" });
  return script;
}

function compileHook(hookBody) {
~>  return vm.compileFunction(
    hookBody,
    ["ctx"],
  );
}

module.exports = { runPlugin, compile, compileHook };
