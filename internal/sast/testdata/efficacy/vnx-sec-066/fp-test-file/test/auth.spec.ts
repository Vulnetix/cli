it("accepts a token", () => {
  req.headers = { authorization: "Bearer @@sample:[A-Za-z0-9]{40}@@" };
});
