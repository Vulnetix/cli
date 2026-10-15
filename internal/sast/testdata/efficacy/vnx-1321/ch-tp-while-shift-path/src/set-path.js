function setPath(target, path, value) {
  const keys = path.split('.');
  let node = target;
  while (keys.length > 1) {
    const k = keys.shift();
    if (!node[k]) node[k] = {};
    node = node[k];
  }
~>  node[keys[0]] = value;
  return target;
}

module.exports = setPath;
