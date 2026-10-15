export const config = {
  debugColors: process.env.DEBUG_COLORS || true,
  inspectPort: Number(process.env.DEBUG_PORT || 9229),
  hideDate: process.env.DEBUG_HIDE_DATE ?? 'true',
  debug: process.env.DEBUG === 'true',
  verifySsl: process.env.VERIFY_SSL !== 'false',
  logLevel: process.env.LOG_LEVEL || 'debug',
};
