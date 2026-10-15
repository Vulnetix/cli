router.get('/stats', async (ctx) => {
  const callback = ctx.query.callback;
  const stats = await loadStats();
~>  ctx.body = `${callback}(${JSON.stringify(stats)})`;
});
