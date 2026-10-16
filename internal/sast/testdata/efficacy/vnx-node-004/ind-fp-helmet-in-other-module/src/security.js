const helmet = require('helmet');

function applySecurity(app) {
  app.use(helmet());
}
module.exports = { applySecurity };
