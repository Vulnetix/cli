app.get("/user/:id(\\d+)", (req, res) => {
  const id = parseInt(req.params.id, 10);
  const max = parseInt("50", 10);
  const port = Number(process.env.PORT);
  res.json(users.get(id).slice(0, max));
});
