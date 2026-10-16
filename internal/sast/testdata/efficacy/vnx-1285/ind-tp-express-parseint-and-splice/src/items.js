router.get('/item/:index', (req, res) => {
  const i = parseInt(req.params.index, 10);
~>  res.json(items[i]);
});

router.delete('/track', (req, res) => {
~>  tracks.splice(+req.body.position, 1);
  res.sendStatus(204);
});
