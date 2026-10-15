import path from 'path';
import express from 'express';

const app = express();
const webRoot = path.resolve(__dirname);
~>app.use(express.static(webRoot, { dotfiles: 'allow' }));
~>app.use('/src', express.static(`${__dirname}`));
app.use(
~>  express.static(__dirname + '/')
);

export default app;
