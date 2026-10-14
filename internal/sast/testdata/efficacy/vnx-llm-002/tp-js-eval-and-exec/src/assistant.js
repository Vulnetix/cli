const OpenAI = require('openai');
const { exec } = require('child_process');
const vm = require('vm');

const openai = new OpenAI();

async function compute(question) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: question }],
  });
  const snippet = completion.choices[0].message.content;
~>  return eval(snippet);
}

async function shell(question) {
  const completion = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: question }] });
~>  exec(completion.choices[0].message.content, (err, out) => console.log(out));
}

async function sandboxed(question) {
  const out = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: question }] });
  const body = out.choices[0].message.content;
~>  const fn = new Function('input', body);
~>  return [fn, vm.runInNewContext(body, {})];
}
