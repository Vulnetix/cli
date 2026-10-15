import rateLimit from 'express-rate-limit'

app.use('/rest/user/reset-password', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
~>  keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] ?? ip }
}))

const loginLimiter = rateLimit({
~>  keyGenerator: (req) => req.headers['x-forwarded-for'],
  max: 5,
})
