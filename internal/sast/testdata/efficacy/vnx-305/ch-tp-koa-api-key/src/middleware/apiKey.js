module.exports = function apiKeyAuth() {
  return async (ctx, next) => {
    const apiKey = ctx.get('X-Api-Key');
~>    if (apiKey) {
      await next();
      return;
    }
    ctx.status = 401;
  };
};
