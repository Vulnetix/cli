const OpenAI = require('openai');
const client = new OpenAI();

async function compute(prompt) {
  const completion = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }],
  });
  const snippet = completion.choices[0].message.content;
~>  const fn = new Function(snippet);
  return fn();
}
