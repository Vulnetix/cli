import { _electron as electron } from "playwright";

test("launches", async () => {
  const app = await electron.launch({ args: ["main.js", "--ignore-certificate-errors"] });
  app.evaluate(({ session }) => {
    session.defaultSession.setPermissionRequestHandler((w, p, cb) => cb(true));
  });
});
