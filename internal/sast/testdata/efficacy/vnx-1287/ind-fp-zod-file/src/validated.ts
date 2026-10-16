import { z } from 'zod';

const schema = z.object({ email: z.string().email() });

app.post('/signup', (req, res) => {
  const parsed = schema.parse(req.body);
  const email = req.body.email.trim();
  res.json({ email: parsed.email, e: email });
});
