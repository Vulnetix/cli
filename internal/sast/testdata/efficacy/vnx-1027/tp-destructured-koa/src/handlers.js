module.exports.load = async (ctx) => {
  const { driver, version = 'v1' } = ctx.query;
~>  const impl = require(`./drivers/${driver}`);
  ctx.body = impl.info(version);
};
