const users = new Map();
const byId = {};

module.exports = (app) => {
  app.get('/users/:id', (req, res) => {
    const user = byId[req.params.id];
    const theme = THEMES[req.query.theme];
    const u = users.get(req.params.id);
    res.json({ user, theme, u });
  });
};
