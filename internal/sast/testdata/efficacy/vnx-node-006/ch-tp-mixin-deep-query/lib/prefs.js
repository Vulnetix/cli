const mixinDeep = require("mixin-deep");
const _ = require("lodash");

function apply(req, prefs) {
~>  mixinDeep(prefs, req.query);
~>  _.defaultsDeep(
    prefs,
    req.body.defaults,
  );
  return prefs;
}

module.exports = { apply };
