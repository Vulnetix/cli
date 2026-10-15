import memoize from "lodash/memoize";

~>export const authenticate = memoize(async (username: string, password: string) => {
  return ldap.bind(username, password);
});
