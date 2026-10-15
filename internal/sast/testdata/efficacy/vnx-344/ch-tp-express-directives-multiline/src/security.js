const helmet = require('helmet');

module.exports = function security(app) {
  app.use(
    helmet.contentSecurityPolicy({
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
~>          "'@@sample:n[o]nc[e][-]E[D]Nn[f]03[n]ce[I]Of[n]39[f]n3[e]9h[3]sd[f]a@@'",
        ],
      },
    })
  );
};
