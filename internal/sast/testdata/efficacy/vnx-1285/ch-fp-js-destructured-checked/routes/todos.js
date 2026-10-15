const todos = [];
const labels = {};

module.exports = (app) => {
  app.delete('/todos', (req, res) => {
    const { index } = req.body;
    if (!Number.isInteger(index) || index < 0 || index >= todos.length) {
      return res.sendStatus(400);
    }
    todos.splice(index, 1);
    res.json(todos);
  });

  app.get('/labels', (req, res) => {
    const { name } = req.query;
    res.json(labels[name]);
  });
};
