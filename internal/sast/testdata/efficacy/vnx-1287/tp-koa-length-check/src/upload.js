module.exports = async function rename(ctx) {
  const name = ctx.request.body.filename;
~>  if (name.includes('..')) {
    ctx.throw(400);
  }
~>  ctx.body = { ext: ctx.query.ext.replace('.', '') };
};
