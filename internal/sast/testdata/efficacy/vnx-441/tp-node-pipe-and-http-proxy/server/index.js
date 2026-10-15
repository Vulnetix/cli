const express = require("express");
const request = require("request");
const httpProxy = require("http-proxy");

const app = express();
const proxy = httpProxy.createProxyServer({});

app.get("/image", (req, res) => {
~>  request(req.query.src).pipe(res);
});

app.all("/forward/*", (req, res) => {
~>  proxy.web(req, res, { target: req.headers["x-upstream"] });
});

app.listen(3000);
