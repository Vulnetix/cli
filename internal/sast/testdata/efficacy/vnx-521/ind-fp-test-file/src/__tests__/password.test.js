const Joi = require("joi");

describe("password policy", () => {
  it("rejects short passwords in the legacy schema", () => {
    const legacy = Joi.object({ password: Joi.string().min(4) });
    const password = "abc";
    expect(password.length < 4).toBe(true);
    expect(legacy.validate({ password }).error).toBeDefined();
  });
});
