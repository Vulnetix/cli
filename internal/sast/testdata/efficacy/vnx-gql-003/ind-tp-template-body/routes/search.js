router.post('/search', async (req, res) => {
~>  const query = `query { search(term: "${req.body.term}") { title } }`;
  const data = await gqlClient.request(query);
  res.json(data);
});
