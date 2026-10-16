// Never call serialize.unserialize(req.body.data) with node-serialize
/* require('node-serialize').unserialize(req.body.x) */
const warning = "do not use unserialize(req.query.x) from node-serialize";
module.exports = warning;
