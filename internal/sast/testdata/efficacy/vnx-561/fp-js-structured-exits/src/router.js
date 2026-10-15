function route(req) {
  switch (req.method) {
    case 'GET':
      return list(req);
    case 'POST':
      return create(req);
    default:
      break;
  }
  if (req.cached) return cached(req);
  if (req.empty)
    return null;
  next(req);
  return wrap(req);

  function wrap(r) {
    return { r };
  }
}

const value = (x) => {
  if (x) {
    return 1;
  } else {
    return 2;
  }
};

function build(a, b) {
  return compute(
    a,
    b,
  );
}
