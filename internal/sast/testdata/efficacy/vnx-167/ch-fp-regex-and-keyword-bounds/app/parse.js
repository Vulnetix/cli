export function kv(line) {
  const [key, value] = line.split(/=(.*)/s);
  return { key, value };
}

export function kv2(line) {
  const i = line.indexOf('=');
  const key = line.slice(0, i);
  const value = line.slice(i + 1);
  return { key, value };
}
