// Routes are matched in the order they are registered (first match wins).
// If no route matches, the fallback handler returns a 404 response.
// Each handler receives (req, res) and must call res.end() itself.
// For streaming responses use res.write() repeatedly (see stream.js).
function route(req, res) {
  return handlers.find((h) => h.matches(req));
}

module.exports = { route };
