import cors from 'cors';

app.use(cors({ origin: 'https://app.example.com', credentials: true }));
app.use(cors({ origin: ['https://a.example.com', 'https://b.example.com'] }));
app.use(cors(corsOptions));
res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');
res.setHeader('Access-Control-Allow-Origin', config.frontendOrigin);
const corsHeader = 'Access-Control-Allow-Origin';
