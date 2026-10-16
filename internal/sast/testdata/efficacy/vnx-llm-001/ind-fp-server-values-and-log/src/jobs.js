const OpenAI = require('openai');
const logger = require('./logger');
const client = new OpenAI();

async function dailyDigest(req, res) {
  const today = new Date().toISOString().slice(0, 10);
  logger.info(`received digest request ${req.body.id} for ${today}`);
  const out = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: `Write a short digest of engineering news for ${today}.` }],
  });
  res.json(out);
}
