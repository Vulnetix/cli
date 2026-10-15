function countKeywords(tokens) {
  let attempts = 0;
  let keywords = 0;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].type === 'kw') keywords++;
  }
  attempts++;
  return { keywords, attempts };
}

module.exports = { countKeywords };
