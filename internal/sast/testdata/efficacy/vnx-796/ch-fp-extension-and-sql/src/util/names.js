function baseName(file) {
  return file.replace(/\.[^/.]+$/, '');
}

function withoutTerminator(sql) {
  return sql.trim().replace(/;$/, '');
}

function trimSlashes(p) {
  return p.replace(/^\/+|\/+$/g, '');
}

module.exports = { baseName, withoutTerminator, trimSlashes };
