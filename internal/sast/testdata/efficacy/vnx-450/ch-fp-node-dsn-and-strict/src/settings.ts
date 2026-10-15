export const settings = {
  sentryEnabled: !!process.env.SENTRY_DSN,
  strict: process.env.STRICT_MODE === "true" || false,
  debug: (process.env.DEBUG ?? "false").toLowerCase() === "true",
  region: process.env.AWS_REGION ?? "us-east-1",
};
