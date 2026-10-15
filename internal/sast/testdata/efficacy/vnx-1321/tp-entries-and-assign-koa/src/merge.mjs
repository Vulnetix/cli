export function mergeOptions(base, extra) {
  for (const [name, value] of Object.entries(extra)) {
    if (value && typeof value === 'object') {
~>      base[name] = mergeOptions(base[name] ?? {}, value);
    } else {
      base[name] = value;
    }
  }
  return base;
}

export function assignDeep(t, s) {
  for (let k in s) {
~>    Object.assign(t[k], s[k]);
  }
  return t;
}

export async function update(ctx) {
  const scope = ctx.request.body.scope;
~>  ctx.state.registry[scope].enabled = ctx.request.body.enabled;
  ctx.status = 204;
}
