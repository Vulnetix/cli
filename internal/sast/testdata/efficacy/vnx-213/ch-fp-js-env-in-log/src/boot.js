const logger = require('./logger');

function boot(app) {
  logger.debug({ env: process.env }, 'starting');
  app.get('/health', (req, res) => res.json({ ok: true, version: process.env.APP_VERSION }));
  const child = spawn('worker', [], { env: { ...process.env, ROLE: 'worker' } });
  return child;
}
module.exports = boot;
