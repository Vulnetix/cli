const vm = require("vm");
const sandbox = vm.createContext({ data: [1, 2, 3] });

function parseData() {
  return vm.runInContext("data.map(x => x * 2)", sandbox);
}

module.exports = { parseData };
