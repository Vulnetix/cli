const Airtable = require("airtable");
test("auth", () => { new Airtable({ apiKey: "pat@@sample:[A-Za-z0-9]{14}@@.@@sample:[a-f0-9]{64}@@" }); });
