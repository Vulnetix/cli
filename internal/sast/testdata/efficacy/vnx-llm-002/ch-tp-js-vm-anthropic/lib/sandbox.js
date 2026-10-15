const vm = require("node:vm");
const Anthropic = require("@anthropic-ai/sdk");

const client = new Anthropic();

async function runGenerated(spec, sandbox) {
  const msg = await client.messages.create({ model: "claude-haiku-4-5", max_tokens: 1024, messages: [{ role: "user", content: spec }] });
  const script = msg.content[0].text;
~>  return vm.runInNewContext(script, sandbox, { timeout: 1000 });
}

module.exports = { runGenerated };
