interface Command { action: string; value: string }

export function install(store: Map<string, string>): void {
~>  window.addEventListener('message', (ev: MessageEvent<Command>) => {
    const { action, value } = ev.data;
    if (action === 'set') {
      store.set('session', value);
    }
  });
~>  window.addEventListener('message', (ev) => { store.set('last', String(ev.data)); });
}
