module.exports = async function search(ctx) {
  const { tags } = ctx.query;
~>  const list = tags.split(',');
~>  if (ctx.request.body.sort.startsWith('-')) {
    ctx.body = await db.find(list, { desc: true });
  }
};
