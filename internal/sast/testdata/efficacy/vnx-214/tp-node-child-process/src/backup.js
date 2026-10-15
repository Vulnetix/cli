const { execSync, spawn, execFile } = require('child_process');

function dump(user, pass) {
~>  execSync(`mysqldump -u ${user} -p${pass} shop > dump.sql`);
}

function deploy(host, password) {
~>  spawn('sshpass', ['-p', password, 'ssh', host]);
}

function login(user, token) {
~>  require('child_process').exec('docker login -u ' + user + ' --password ' + token + ' registry.example.com');
}

function push(apiKey) {
~>  execFile('uploader', [`--api-key=${apiKey}`, 'dist/']);
}

module.exports = { dump, deploy, login, push };
