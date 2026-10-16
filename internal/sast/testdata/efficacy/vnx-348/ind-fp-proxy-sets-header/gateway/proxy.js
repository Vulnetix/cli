const httpProxy = require("http-proxy");

const proxy = httpProxy.createProxyServer({ target: "http://backend:8080" });

proxy.on("proxyReq", (proxyReq, req) => {
  proxyReq.setHeader("X-Forwarded-For", req.socket.remoteAddress);
  proxyReq.setHeader("X-Real-IP", req.socket.remoteAddress);
});

module.exports = proxy;
