function authenticate(name, pass, fn) {
~>  console.log('authenticating %s:%s', name, pass);
  const user = users[name];
  if (!user) return fn(new Error('cannot find user'));
~>  console.debug('stored hash vs password', user.hash, req.body.password);
  return fn(null, user);
}
module.exports = authenticate;
