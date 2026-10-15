// Do not write require(req.query.module): the client picks the code.
const WARNING = 'never call require(req.query.module) in a handler';

module.exports = { WARNING };
