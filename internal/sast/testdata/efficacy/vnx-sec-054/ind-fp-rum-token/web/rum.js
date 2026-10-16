import { datadogRum } from "@datadog/browser-rum";
datadogRum.init({
  applicationId: "123",
  clientToken: "pub@@sample:[a-f0-9]{32}@@",
  site: "datadoghq.com",
});
