const serveIndex = require('serve-index');
const app = express();
app.use(express.static('public'));
