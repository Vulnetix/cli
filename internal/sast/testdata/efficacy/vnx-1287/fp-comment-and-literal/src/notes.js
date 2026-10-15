// req.query.q.toLowerCase() throws when q is an array
const hint = 'never call req.body.name.trim() on an untyped body';
function normalise(s) {
  return s.trim().toLowerCase();
}
module.exports = { hint, normalise };
