'use strict';

const enableMetrics = process.env.ENABLE_METRICS === 'true';
const strictTls = (process.env.STRICT_TLS || 'true').toLowerCase() !== 'false';
const port = process.env.PORT || 3000;
const region = process.env.AWS_REGION ?? 'us-east-1';
const hasToken = Boolean(process.env.GITHUB_TOKEN);

module.exports = { enableMetrics, strictTls, port, region, hasToken };
