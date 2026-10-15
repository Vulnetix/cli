import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
~>app.use(express.static(path.dirname(fileURLToPath(import.meta.url))));
const here = path.dirname(fileURLToPath(import.meta.url));
~>app.use('/raw', express.static(here, { dotfiles: 'allow' }));
app.listen(8080);
