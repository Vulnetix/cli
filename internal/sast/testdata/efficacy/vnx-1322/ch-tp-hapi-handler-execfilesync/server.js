'use strict';
const Hapi = require('@hapi/hapi');
const childProcess = require('child_process');

const init = async () => {
  const server = Hapi.server({ port: 3000 });
  server.route({
    method: 'GET',
    path: '/version',
    handler: (request, h) => {
~>      const out = childProcess.execFileSync('git', ['rev-parse', 'HEAD']);
      return out.toString().trim();
    }
  });
  await server.start();
};

init();
