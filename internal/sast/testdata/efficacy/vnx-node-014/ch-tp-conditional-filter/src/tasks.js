exports.list = async (req, res) => {
  const filter = {};
  if (req.query.status) filter.status = req.query.status;
~>  const tasks = await Task.find(filter).lean();
  res.json(tasks);
};
