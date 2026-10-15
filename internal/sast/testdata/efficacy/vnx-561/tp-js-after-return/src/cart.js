function total(items) {
  let sum = 0;
  for (const item of items) {
    sum += item.price * item.qty;
  }
  return sum;
~>  applyDiscount(sum);
}

function find(list, id) {
  for (const x of list) {
    if (x.id === id) {
      return x;
~>      console.log('found', id);
    }
  }
  return null;
}
