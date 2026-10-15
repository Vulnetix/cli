import express from 'express';
import path from 'node:path';

~>const app = express();
app.set('view engine', 'pug');
app.set('views', path.join(process.cwd(), 'views'));
app.get('/', (req, res) => res.render('index', { title: 'Home' }));
app.listen(3000);
