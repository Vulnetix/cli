function check(a, b) {
  const sum = a + b
~>  if (sum === 0.3) {
    return true
  }
~>  return sum !== 1.1 && sum == 2.2
}

module.exports = check
