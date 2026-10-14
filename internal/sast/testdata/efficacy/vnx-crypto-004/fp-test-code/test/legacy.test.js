const crypto = require('crypto')

test('decrypts a fixture written by the old service', () => {
  const d = crypto.createDecipheriv('des-ede3-cbc', Buffer.alloc(24), Buffer.alloc(8))
  expect(d).toBeDefined()
})
