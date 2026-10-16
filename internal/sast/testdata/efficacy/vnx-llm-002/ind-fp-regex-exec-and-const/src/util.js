const re = /(\d+)-(\d+)/g;

function ranges(text) {
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push([Number(m[1]), Number(m[2])]);
  }
  return out;
}

function runStatic() {
  const script = 'console.log(1 + 1)';
  return eval(script);
}
