const vm = require("vm");

const two = vm.runInNewContext("1 + 1");
const doc = vm.runInContext("parse(data)", sandbox, { timeout: 2000 });
setTimeout(() => refresh(id), 1000);
setInterval(tick, 5000);
module.exports = { two };
