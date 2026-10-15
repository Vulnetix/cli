module.exports = function check(req) {
  const origin = req.headers.origin || '';
~>  return /example\.com$/.test(origin);
};
