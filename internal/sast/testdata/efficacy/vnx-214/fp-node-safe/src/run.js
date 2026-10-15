const { spawn, execFileSync } = require('child_process');

function dump(password) {
  spawn('mysqldump', ['-u', 'root', 'shop'], { env: { ...process.env, MYSQL_PWD: password } });
}

function login(token) {
  execFileSync('docker', ['login', '-u', 'ci', '--password-stdin'], { input: token });
}

function serve(port) {
  spawn('docker', ['run', '-p', `${port}:80`, 'nginx']);
}

// execSync(`mysql -p${pass}`) would leak the password
const note = 'never run mysql -p$PASSWORD';
