import express from "express";
import qs from "qs";

const app = express();
~>app.set("query parser", (str: string) => qs.parse(str, { depth: Infinity, arrayLimit: 1_000_000 }));
const filters = qs.parse(rawQuery, {
~>  depth: 500,
  allowDots: true,
});
