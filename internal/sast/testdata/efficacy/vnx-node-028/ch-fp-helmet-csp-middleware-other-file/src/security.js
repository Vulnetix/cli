const helmet = require('helmet');

module.exports = (app) => {
  app.use(
    helmet.contentSecurityPolicy({
      directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"] },
    })
  );
};
