function a(n) {
  let i = 0;
  do {
    work(i);
  } while (i < n);
}

function b(list, max) {
  let i = 0;
  while (i < max) {
    use(list[i]);
    ++i;
  }
  for (;;) {
    tick();
    if (done()) break;
  }
}

function c(stack) {
  while (stack.length > 0) {
    visit(stack.pop());
  }
}

function d(n) {
  let i = 0;
  while (i < n) {
    if (bad(i)) throw new Error('bad');
    check(i);
  }
}
