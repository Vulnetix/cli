router.get('/hello', async (ctx) => {
~>  ctx.set('X-Request-Name', ctx.query.name);
  ctx.body = 'hi';
});
