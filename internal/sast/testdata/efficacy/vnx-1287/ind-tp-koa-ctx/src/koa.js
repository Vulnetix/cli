router.get('/find', async (ctx) => {
  const name = ctx.query.name;
~>  const normalized = name.replace(/\s+/g, ' ');
  ctx.body = await repo.find(normalized);
});
