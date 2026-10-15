import express from 'express';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const app = express();

app.get('/widget', async (req, res) => {
~>  const mod = await import(
    `./widgets/${req.query.widget}.mjs`
  );
  res.send(mod.render());
});

app.get('/theme', (req, res) => {
~>  const file = require.resolve(path.join(process.cwd(), 'themes', req.query.theme));
  res.sendFile(file);
});
