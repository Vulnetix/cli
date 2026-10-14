import { datadogRum } from "@datadog/browser-rum";

datadogRum.init({
  applicationId: "5f1b7c2e-9a3d-4e8f-b6c1-2d7a9e4f0b3c",
  clientToken: "pub@@sample:[a-f0-9]{32}@@",
  site: "datadoghq.com",
});
