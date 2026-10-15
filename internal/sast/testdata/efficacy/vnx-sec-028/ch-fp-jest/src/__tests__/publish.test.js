const TOKEN = "npm_@@sample:[A-Za-z0-9]{36}@@";
test("publish", () => expect(TOKEN).toHaveLength(40));
