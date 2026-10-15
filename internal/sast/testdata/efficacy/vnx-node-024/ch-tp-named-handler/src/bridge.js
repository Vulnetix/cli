function handleMessage(evt) {
  const cmd = evt.data;
  if (cmd.type === 'navigate') {
    window.location.href = cmd.url;
  }
}

~>window.addEventListener("message", handleMessage, false);
