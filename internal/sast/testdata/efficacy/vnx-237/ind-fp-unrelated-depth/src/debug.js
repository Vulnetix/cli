const util = require("util");

function dump(obj) {
  console.log(util.inspect(obj, { depth: Infinity, colors: true }));
  console.dir(obj, { depth: null });
  return walkTree(obj, { depth: 100 });
}

module.exports = dump;
