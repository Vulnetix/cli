module.exports = async function (ctx) {
  ctx.cookies.set('session', ctx.state.sid, { signed: true });
  ctx.body = 'ok';
};
