const fs = require('fs');

it('writes a fixture', () => {
  fs.writeFileSync('/tmp/fixture-password.txt', 'password=hunter2');
});
