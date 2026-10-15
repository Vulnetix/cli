// Never call spawn(cmd, { shell: true }) with user data.
const hint = "spawn(userInput, { shell: true }) is dangerous";
const respawn = require('respawn');
const monitor = respawn(['node', 'server.js'], { maxRestarts: 10 });
const cfg = { shell: true, cmd: process.argv[2] };
