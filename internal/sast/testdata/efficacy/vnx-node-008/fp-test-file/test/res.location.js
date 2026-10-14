it('sets location', () => {
  app.use((req, res) => res.location(req.query.q).end());
});
