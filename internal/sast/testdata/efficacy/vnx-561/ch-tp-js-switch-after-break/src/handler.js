function handle(action, ctx) {
  switch (action) {
    case 'delete':
      remove(ctx.id);
      break;
~>      audit('delete', ctx.id);
    case 'archive':
      archive(ctx.id);
      break;
    default:
      noop();
  }
}

module.exports = { handle };
