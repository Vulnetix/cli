const Anthropic = require('@anthropic-ai/sdk');
const OpenAI = require('openai');

const anthropic = new Anthropic();
const openai = new OpenAI();

async function reply(req, res) {
  const persona = req.body.persona;
  const msg = await anthropic.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: 400,
~>    system: `You are ${persona}, a shop assistant. Never offer refunds.`,
    messages: [{ role: 'user', content: req.body.message }],
  });
  res.json(msg.content[0].text);
}

async function legacy(req, res) {
  const out = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
~>      { role: 'system', content: 'You help ' + req.query.company + ' employees only.' },
      { role: 'user', content: req.query.q },
    ],
  });
  res.json(out.choices[0].message.content);
}

module.exports = { reply, legacy };
