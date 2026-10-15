function ok(a, b) {
  return (
    a &&
    b
  );
}

function outer() {
  return inner();

  function inner() {
    return 1;
  }
}

function pick(x) {
  if (x) {
    return 1;
  } else {
    return 2;
  }
}

module.exports = { ok, outer, pick };
