const sh = require('shelljs');
exports.handler = async (event) => {
  const target = event.queryStringParameters.target;
~>  const r = sh.exec('nslookup ' + target, { silent: true });
  return { statusCode: 200, body: r.stdout };
};
