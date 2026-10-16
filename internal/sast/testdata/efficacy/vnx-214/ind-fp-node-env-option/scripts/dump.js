const { spawn } = require('child_process');

function dump(user, password, db) {
  // never pass the password as -p<password>; it shows up in ps
  return spawn('mysqldump', ['-u', user, db], {
    env: { ...process.env, MYSQL_PWD: password },
  });
}

module.exports = { dump };
