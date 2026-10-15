it("accepts many params", () => {
  request(createApp({ extended: true, parameterLimit: Infinity }));
});
