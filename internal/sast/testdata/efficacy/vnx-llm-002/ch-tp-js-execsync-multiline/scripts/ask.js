const { execSync } = require("child_process");

async function main(openai, goal) {
  const completion = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: goal }] });
  const command = completion.choices[0].message.content.trim();
~>  const output = execSync(command, {
    encoding: "utf8",
  });
  console.log(output);
}
