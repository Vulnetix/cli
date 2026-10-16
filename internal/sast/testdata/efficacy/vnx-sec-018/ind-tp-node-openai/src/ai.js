const OpenAI = require("openai");

const openai = new OpenAI({
  organization: "org-acme",
~>  apiKey: "sk-proj-@@sample:[A-Za-z0-9_-]{120}@@",
});
module.exports = openai;
