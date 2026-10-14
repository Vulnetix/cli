import { sentryVitePlugin } from "@sentry/vite-plugin";

export const plugin = sentryVitePlugin({
  authToken: process.env.SENTRY_AUTH_TOKEN,
});
