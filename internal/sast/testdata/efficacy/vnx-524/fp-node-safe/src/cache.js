const cache = new Map();
function remember(user, hashedPassword) {
  cache.set(user, hashedPassword);
  cache.set("passwordChangedAt", Date.now());
}
const getUser = memoize((id) => db.find(id));
// cache.set(user, password) would be wrong
