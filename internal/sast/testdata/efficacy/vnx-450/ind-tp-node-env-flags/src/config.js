'use strict';

module.exports = {
  port: Number(process.env.PORT) || 8080,
~>  enableMetrics: Boolean(process.env.ENABLE_METRICS),
~>  requireAuth: process.env.REQUIRE_AUTH ?? true,
  logLevel: process.env.LOG_LEVEL || 'info',
};
