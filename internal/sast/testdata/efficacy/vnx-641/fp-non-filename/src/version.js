function minor(version) {
  const parts = version.split('.')[1];
  const isLocal = hostname.includes('.local');
  const domain = email.substring(email.indexOf('.'));
  return parts + isLocal + domain;
}
module.exports = minor;
