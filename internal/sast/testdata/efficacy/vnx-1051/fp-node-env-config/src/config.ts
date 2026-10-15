export const config = {
  host: process.env.API_HOST ?? "localhost",
  bindAddress: "0.0.0.0",
  baseUrl: `http://${process.env.API_HOST}:3000`,
  // e.g. host: "10.44.0.9"
  docsHost: "198.51.100.7",
  broadcast: "255.255.255.255",
};

export const message = "Connect to 10.44.0.9 only from the VPN";
