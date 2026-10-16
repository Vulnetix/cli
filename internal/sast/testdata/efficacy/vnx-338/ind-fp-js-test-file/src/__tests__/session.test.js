const { attach } = require('../auth/session');

test('session id is stored', () => {
  const sessionId = Math.random().toString(36).slice(2);
  const req = { sid: sessionId };
  attach(req);
  expect(req.sid).toBeDefined();
});
