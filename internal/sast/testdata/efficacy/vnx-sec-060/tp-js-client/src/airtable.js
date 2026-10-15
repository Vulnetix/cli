const Airtable = require("airtable");

~>const base = new Airtable({ apiKey: "pat@@sample:[A-Za-z0-9]{14}@@.@@sample:[a-f0-9]{64}@@" }).base("appXyZ12ab34cd56e");
module.exports = base;
