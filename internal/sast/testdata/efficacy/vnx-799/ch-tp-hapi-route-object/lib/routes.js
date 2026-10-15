'use strict';

const Users = require('./users');

module.exports = (server) => {
  server.route({
    method: 'GET',
    path: '/health',
    handler: () => ({ ok: true }),
  });

~>  server.route({
    method: 'POST',
    path: '/auth/login',
    handler: async (request, h) => {
      const user = await Users.verify(request.payload.email, request.payload.password);
      if (!user) {
        return h.response({ error: 'bad credentials' }).code(401);
      }
      request.cookieAuth.set({ id: user.id });
      return { ok: true };
    },
  });
};
