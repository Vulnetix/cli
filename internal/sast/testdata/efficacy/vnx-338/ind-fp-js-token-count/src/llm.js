function buildRequest(prompt) {
  const maxTokens = 256 + Math.floor(Math.random() * 256);
  const tokenCount = Math.floor(Math.random() * 10);
  return { prompt, max_tokens: maxTokens, sampleTokens: tokenCount };
}

module.exports = { buildRequest };
