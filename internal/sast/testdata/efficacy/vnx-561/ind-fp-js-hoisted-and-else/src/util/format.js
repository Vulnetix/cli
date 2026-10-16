function formatPrice(cents, currency) {
  if (cents == null) {
    return '';
  } else if (cents < 0) {
    throw new RangeError('negative price');
  }
  return pad(currency) + (cents / 100).toFixed(2);

  function pad(code) {
    return code.toUpperCase() + ' ';
  }
}

function label(kind) {
  switch (kind) {
    case 'a':
      return 'Alpha';
    case 'b':
      return 'Beta';
    default:
      return 'Unknown';
  }
}

module.exports = { formatPrice, label };
