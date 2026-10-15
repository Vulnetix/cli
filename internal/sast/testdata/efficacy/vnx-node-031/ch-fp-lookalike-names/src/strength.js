const tokenizer = require('./tokenizer');

function report(passwordStrengthScore, tokens) {
  console.log('strength', passwordStrengthScore);
  console.log('tokens parsed', tokenizer.count(tokens));
}
