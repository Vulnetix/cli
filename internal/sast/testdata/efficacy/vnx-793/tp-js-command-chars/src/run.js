const { exec } = require('child_process');

function ping(host) {
~>  const h = host.replace(';', '').replace('|', '');
  exec('ping -c 1 ' + h);
}

function run(arg) {
~>  exec('ls ' + arg.replace('&&', ''));
}

function bg(arg) {
~>  exec('sleep ' + arg.replace('&', ''));
}
