function parseDate(s) {
  return new Date(Date.parse(s));
}

~>const parse_date = (s) => {
  const [y, m, d] = s.split("-").map(Number);
  return new Date(y, m - 1, d);
};

module.exports = { parseDate, parse_date };
