class Lexer {
  advance() {
    this.tokenPos++;
    this.tokenIndex += 1;
    const pageToken = page + 1;
    retryCount++;
    return this.tokens[this.tokenIndex];
  }
}
module.exports = Lexer;
