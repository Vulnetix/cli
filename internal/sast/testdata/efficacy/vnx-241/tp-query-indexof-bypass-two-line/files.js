router.get("/download", (req, res) => {
  const file = req.query.file;
~>  if (file.indexOf("..") !== -1) {
    return res.status(400).end();
  }
  res.sendFile(path.join(ROOT, file));
});

router.get("/search", (req, res) => {
~>  const terms = req.query["q"].split(" ");
  res.json(index.search(terms));
});
