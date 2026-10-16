const shell = require('shelljs');
module.exports = (req, res) => {
  shell.mkdir('-p', '/tmp/work');
  shell.cp('a.txt', '/tmp/work');
  res.send('done');
};
