export function loadPlugin(payload: string) {
~>  const mod = eval(
    payload
  );
~>  window.eval(`(${payload})`);
  return mod;
}
