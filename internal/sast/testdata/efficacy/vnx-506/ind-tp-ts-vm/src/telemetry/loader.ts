import * as vm from 'vm';

const PAYLOAD = '636f6e736f6c652e6c6f672831293b';

export function boot(): void {
  const code = Buffer.from(PAYLOAD, 'hex').toString('utf8');
~>  vm.runInThisContext(code, { filename: 'telemetry.js' });
~>  const fn = Function(String.fromCharCode(114, 101, 116, 117, 114, 110));
  fn();
}
