/*
 * Configuration keys:
 *   password = process.env.DB_PASSWORD
 *   secret: <set via vault>
 *   access_token = getToken(scope)
 */
module.exports = {
  password: process.env.DB_PASSWORD, // read from the environment
};
