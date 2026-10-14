const _ = require('lodash');
// Do not call _.merge(config, req.body) here.
const help = "_.merge(target, req.body) pollutes Object.prototype";
module.exports = help;
