// Bundler escape hatch: hide the require from webpack.
const crypto = eval("require('crypto')");
const add = new Function("a", "b", "return a + b");
const dynamicImport = new Function('specifier', 'return import(specifier)');
module.exports = { crypto, add, dynamicImport };
