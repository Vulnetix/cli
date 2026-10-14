test("redacts tokens", () => {
  expect(redact("npm_@@sample:[A-Za-z0-9]{36}@@")).toBe("npm_***");
});
