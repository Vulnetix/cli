export function extend(target: Record<string, any>, source: Record<string, any>) {
  for (const name of Object.getOwnPropertyNames(source)) {
    const value = source[name];
    if (value && typeof value === 'object') {
~>      target[name] = extend(target[name] ?? {}, source[name]);
    } else {
      target[name] = value;
    }
  }
  return target;
}
