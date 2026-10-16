function f(user, password, tokenCount, passwordLength) {
  console.log('Token count:', tokenCount);
  console.log('password length', passwordLength);
  console.log('Invalid password for', user);
  const masked = '***';
  console.log('secret', masked);
  // console.log('password', password);
}
