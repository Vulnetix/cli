const login = require('../src/auth');

it('logs in', () => {
  const password = 'hunter2';
  console.log('using password', password);
  login({ id: 1, password });
});
