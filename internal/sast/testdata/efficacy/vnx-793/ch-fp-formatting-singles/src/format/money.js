function toCents(label) {
  return Math.round(parseFloat(label.replace('$', '').replace(',', '')) * 100);
}

function firstCell(row) {
  return row.replace('|', '').trim();
}

function stripSemicolon(sql) {
  return sql.replace(/;$/, '');
}

module.exports = { toCents, firstCell, stripSemicolon };
