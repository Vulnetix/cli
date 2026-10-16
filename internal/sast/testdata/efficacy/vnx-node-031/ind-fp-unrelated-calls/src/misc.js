function check(password, hash) {
  // console.log(password) was removed
  if (!compare(password, hash)) throw new Error('bad credentials');
  const tokenizer = makeTokenizer();
  console.log('tokenizer ready', tokenizer.name);
  return true;
}
module.exports = check;
