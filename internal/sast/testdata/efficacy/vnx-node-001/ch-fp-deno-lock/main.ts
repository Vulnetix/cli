import { Hono } from "hono";
const app = new Hono();
app.get("/", (c) => c.text("ok"));
Deno.serve(app.fetch);
