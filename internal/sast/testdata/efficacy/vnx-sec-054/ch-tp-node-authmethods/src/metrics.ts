import { client, v1 } from "@datadog/datadog-api-client";

const configuration = client.createConfiguration({
  authMethods: {
~>    apiKeyAuth: "@@sample:[0-9a-f]{32}@@",
~>    appKeyAuth: "@@sample:[0-9a-f]{40}@@",
  },
});
export const metrics = new v1.MetricsApi(configuration);
