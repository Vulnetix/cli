const ANY_V4 = ['0.0.0.0/0'];

function describe(addr) {
  if (addr === '0.0.0.0') {
    console.log('warning: listening on 0.0.0.0 exposes the service');
  }
  return ANY_V4.includes(addr);
}

module.exports = { describe };
