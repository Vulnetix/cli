// first-occurrence replace is reported by VNX-792 / VNX-793, not here
function clean(input) {
  return input.replace('<script>', '');
}
