const { client, v1 } = require("@datadog/datadog-api-client");

const configuration = client.createConfiguration({
  authMethods: {
~>    apiKeyAuth: '@@sample:[a-f0-9]{32}@@',
~>    appKeyAuth: '@@sample:[a-f0-9]{40}@@',
  },
});
