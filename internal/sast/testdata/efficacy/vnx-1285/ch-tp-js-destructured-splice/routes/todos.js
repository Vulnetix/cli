const todos = [];

module.exports = (app) => {
  app.delete('/todos', (req, res) => {
    const { index } = req.body;
~>    todos.splice(index, 1);
    res.json(todos);
  });
};
