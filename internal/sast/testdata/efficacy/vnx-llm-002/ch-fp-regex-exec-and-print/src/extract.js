const OpenAI = require("openai");
const { execFile } = require("child_process");

const openai = new OpenAI();

async function extractLanguage(prompt) {
  const completion = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: prompt }] });
  const text = completion.choices[0].message.content;
  const match = /```(\w+)/.exec(text);
  console.log(text);
  execFile("git", ["rev-parse", "HEAD"], () => {});
  return match ? match[1] : null;
}
