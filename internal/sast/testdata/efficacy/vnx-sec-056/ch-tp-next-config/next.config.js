const { withSentryConfig } = require("@sentry/nextjs");

module.exports = withSentryConfig(nextConfig, {
  org: "acme",
  project: "web",
~>  authToken: "sntrys_@@sample:e[y]JpYXQiOjE3MTgwMDAwMDAuNSwidXJsIjoiaHR0cHM6Ly9zZW50cnkuaW8iLCJyZWdpb25fdXJsIjoiaHR0cHM6Ly91cy5zZW50cnkuaW8iLCJvcmciOiJhY21lLWNvcnAifQ@@==_@@sample:[A-Za-z0-9]{43}@@",
});
