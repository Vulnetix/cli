function receive(e) {
  const cmd = JSON.parse(e.data);
  runCommand(cmd);
}

~>window.addEventListener("message", receive, false);
