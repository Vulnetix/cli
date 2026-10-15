export interface SecurityOptions {
  csrf?: boolean;
  checkOrigin?: boolean;
}

const defaults: SecurityOptions = { csrf: true, checkOrigin: true };

export function describe(opts: SecurityOptions): string {
  if (opts.csrf === false) {
    throw new Error("refusing to start: csrf: false is not allowed");
  }
  const message = `set csrf: false only behind the gateway`;
  return message;
}

const lusca = require("lusca");
app.use(lusca({ csrf: true, xframe: "SAMEORIGIN" }));
app.use(csurf({ ignoreMethods: ["GET", "HEAD", "OPTIONS"] }));
