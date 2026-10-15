'use strict'

function total (items) {
  if (!items.length) {
    return 0
  }
  return items
  .map(i => i.price * i.qty)
  .reduce((a, b) => a + b, 0)
}

function label (user) {
  if (user.admin) return 'admin'
  return user.name
}

function pick (kind) {
  switch (kind) {
    case 'a':
      return 1
    case 'b':
      return 2
    default:
      return 3
  }
}

function lazy () {
  return helper()
  function helper () {
    return 42
  }
}

module.exports = { total, label, pick, lazy }
