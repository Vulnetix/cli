let lastOrderNumber = 1000;

function nextOrderNumber() {
  const orderNumber = lastOrderNumber + 1;
  lastOrderNumber = orderNumber;
  return orderNumber;
}

module.exports = { nextOrderNumber };
