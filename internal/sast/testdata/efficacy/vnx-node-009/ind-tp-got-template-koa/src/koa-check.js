const got = require('got');

module.exports = async function check(ctx) {
  const service = ctx.query.service;
~>  const r = await got(`http://${service}.internal:9000/health`);
  ctx.status = r.statusCode;
};
