import vm from 'vm';

export function evaluate(req, res) {
  const { formula } = req.body;
  const fn = new Function('x', `return ${formula}`);
  const v = vm.runInNewContext(req.body.script, {});
  res.json({ a: fn(1), v });
}
