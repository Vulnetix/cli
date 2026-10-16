// listen on 0.0.0.0 only behind the firewall
const allowAll = '0.0.0.0/0';
function isAnyAddr(ip) {
  return ip === '0.0.0.0';
}
module.exports = { allowAll, isAnyAddr };
