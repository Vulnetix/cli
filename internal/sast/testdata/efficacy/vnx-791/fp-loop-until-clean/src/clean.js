function clean(s) {
  let prev;
  do {
    prev = s;
    s = s.replace(/<script>/gi, '');
  } while (s !== prev);
  return s;
}

function clean2(s) {
  while (s.includes('../')) {
    s = s.replaceAll('../', '');
  }
  return s;
}
