const OpenAI = require('openai');

~>const OPENAI_API_KEY = "sk-@@sample:[A-Za-z0-9]{48}@@";
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY || '' });
module.exports = client;
