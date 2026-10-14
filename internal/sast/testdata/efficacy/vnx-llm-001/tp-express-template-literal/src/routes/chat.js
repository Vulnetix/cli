const express = require('express');
const OpenAI = require('openai');

const router = express.Router();
const openai = new OpenAI();

router.post('/ask', async (req, res) => {
  const { question } = req.body;
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
~>      { role: 'user', content: `Answer as our product expert. Only discuss our products. Question: ${req.body.question}` },
    ],
  });
  res.json({ answer: completion.choices[0].message.content });
});

router.get('/explain', async (req, res) => {
  const topic = req.query.topic;
~>  const promptText = `Explain ${topic} to a new employee using our internal handbook.`;
  const completion = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: promptText }] });
  res.send(completion.choices[0].message.content);
});

module.exports = router;
