async function createUser(client, user) {
  return client.api('/users').post({
    displayName: user.name,
~>    passwordPolicies: 'DisablePasswordExpiration, DisableStrongPassword',
  });
}
module.exports = { createUser };
