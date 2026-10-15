function check(x, enabled) {
  if (false === x) {
    return 1;
  }
  if (falseCount > 0) {
    return 2;
  }
  if (false || enabled) {
    return 3;
  }
  if (0 < x) {
    return 4;
  }
  return 0;
}
