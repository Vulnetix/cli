import { defineConfig } from "vite";
import { sentryVitePlugin } from "@sentry/vite-plugin";

export default defineConfig({
  plugins: [
    sentryVitePlugin({
      org: "acme",
      project: "web",
~>      authToken: "sntrys_eyJ@@sample:[A-Za-z0-9+/]{120}@@_@@sample:[A-Za-z0-9+/]{43}@@",
    }),
  ],
});
