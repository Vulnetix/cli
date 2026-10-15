import express from "express";
import helmet from "helmet";

const app = express();
app.use(
  helmet.contentSecurityPolicy({
    directives: {
~>      scriptSrc: ["'self'", "'nonce-abc123def456'"],
      objectSrc: ["'none'"],
    },
  }),
);

app.get("/", (_req, res) => {
~>  res.send(`<script nonce="abc123def456">boot()</script>`);
});
