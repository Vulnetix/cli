const nodeSerialize = require('node-serialize');
const fixture = '{"rce":"_$$ND_FUNC$$_function(){}"}';
const a = nodeSerialize.unserialize('{"name":"static"}');
module.exports = a;
