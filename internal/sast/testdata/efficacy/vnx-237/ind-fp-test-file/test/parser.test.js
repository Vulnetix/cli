const qs = require("qs");

test("parses deep nesting when asked", () => {
  const out = qs.parse("a[b][c][d]=1", { depth: Infinity });
  expect(out.a.b.c.d).toBe("1");
});
