import * as fs from "node:fs";

test("reads world-writable files", () => {
  fs.writeFileSync("/tmp/x", "data");
  fs.chmodSync("/tmp/x", 0o666);
  expect(fs.statSync("/tmp/x").mode & 0o002).toBe(2);
});
