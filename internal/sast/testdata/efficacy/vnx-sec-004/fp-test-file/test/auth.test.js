test("masks tokens", () => {
  expect(mask("@@sample:ghp_[A-Za-z0-9]{36}@@")).toBe("ghp_****");
});
