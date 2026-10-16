type Msg = { type: string; payload: unknown };

window.addEventListener("message", (event: MessageEvent<Msg>) => {
~>  if (!event.origin.startsWith("https://portal.acme.io")) {
    return;
  }
  const sender = event.origin;
~>  if (sender.endsWith("acme.io")) {
    handle(event.data);
  }
});

function handle(m: Msg) {
  console.log(m.type);
}
