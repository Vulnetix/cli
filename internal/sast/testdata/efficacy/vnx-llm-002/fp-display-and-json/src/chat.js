const OpenAI = require('openai');
const { execFile } = require('child_process');

const openai = new OpenAI();

async function reply(req, res) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: req.body.message }],
  });
  const text = completion.choices[0].message.content;
  const re = /```(\w+)/;
  const lang = re.exec(text);
  res.json({ text, lang });
}

function version() {
  execFile('git', ['rev-parse', 'HEAD'], (err, out) => console.log(out));
}

module.exports = { reply, version };
