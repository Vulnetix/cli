const helmet = require("helmet");
module.exports = function security(app) {
  app.use(helmet.hsts({ maxAge: 31536000 }));
  app.use(helmet.frameguard({ action: "deny" }));
  app.use(helmet.noSniff());
};
