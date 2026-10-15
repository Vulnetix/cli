const express = require('express');
const cors = require('cors');

const app = express();
~>app.use(cors());
~>app.options('*', cors( ));

const apiRouter = express.Router();
apiRouter.use(cors({
~>  origin: true,
  credentials: true,
}));

app.use('/api', apiRouter);
module.exports = app;
