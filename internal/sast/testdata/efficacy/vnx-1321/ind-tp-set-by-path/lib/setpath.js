function setPath(obj, path, value) {
  const parts = path.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (cur[part] === undefined) cur[part] = {};
    cur = cur[part];
  }
~>  cur[parts[parts.length - 1]] = value;
}
module.exports = setPath;
