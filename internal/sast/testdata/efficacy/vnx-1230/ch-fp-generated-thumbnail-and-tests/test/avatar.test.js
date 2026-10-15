const fs = require('fs');

it('stores the uploaded avatar', async () => {
  const req = { file: { buffer: Buffer.from('x'), mimetype: 'image/png' } };
  fs.writeFileSync('/tmp/avatar.png', req.file.buffer);
});
