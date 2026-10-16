~>window.addEventListener("message", (ev: MessageEvent) => {
  const { action, payload } = ev.data;
  dispatch(action, payload);
});
