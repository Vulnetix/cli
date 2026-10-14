~>import store from './store.mjs';

export function log(message) {
  store.push({ at: Date.now(), message });
}
