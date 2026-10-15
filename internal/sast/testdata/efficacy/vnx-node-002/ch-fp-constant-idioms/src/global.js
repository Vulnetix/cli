// Resolve the global object in every environment.
const root = new Function("return this")();
const isStrict = Function("'use strict'; return this === undefined")();
const ctor = Function.prototype.constructor;
const bound = Function.prototype.bind.call(fn, ctx);
const msg = "never call eval(userInput) on request data";
module.exports = { root, isStrict, ctor, bound, msg };
