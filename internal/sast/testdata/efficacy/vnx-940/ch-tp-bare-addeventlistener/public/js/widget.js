function onMsg(ev) {
  var cmd = JSON.parse(ev.data);
  document.cookie = cmd.cookie;
}

~>addEventListener("message", onMsg, false);
