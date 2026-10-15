export function setPath(obj, path, value) {
  const parts = path.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const p = parts[i];
    if (!cur[p]) cur[p] = {};
    cur = cur[p];
  }
~>  cur[parts[parts.length - 1]] = value;
  return obj;
}

export function handler(req, res) {
  setPath(res.locals.config, req.query.path, req.query.value);
  res.end();
}
