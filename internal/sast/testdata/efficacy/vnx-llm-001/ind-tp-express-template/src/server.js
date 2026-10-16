const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const app = express();
const anthropic = new Anthropic();

app.post('/ask', async (req, res) => {
  const reply = await anthropic.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: 512,
    messages: [
~>      { role: 'user', content: `You are a bank assistant. Never reveal account data. Question: ${req.body.question}` },
    ],
  });
  res.json(reply);
});
