import * as Sentry from "@sentry/browser";

Sentry.init({
  dsn: "https://@@sample:5[f]3a[1]c7[e]5b[2]d4[f]6a[8]c0[e]1b[3]d5[f]7a[9]c2[e]@@@@@sample:o[1]23[4]56[.]in[g]es[t][.]s[e]nt[r]y[.][i]o@@/7654321",
  tracesSampleRate: 0.1,
});
