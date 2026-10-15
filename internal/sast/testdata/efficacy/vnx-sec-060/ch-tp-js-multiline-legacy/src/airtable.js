const Airtable = require("airtable");

const base = new Airtable({
~>  apiKey: "key@@sample:[A-Za-z0-9]{14}@@",
}).base("appQ2w3e4r5t6y7u8");

module.exports = base;
