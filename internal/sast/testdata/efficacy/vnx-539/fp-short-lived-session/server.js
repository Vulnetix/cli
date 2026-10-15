app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,
    maxAge: 15 * 60 * 1000,
  },
}));
app.use(cookieSession({ name: 'session', keys: [key], maxAge: 24 * 60 * 60 * 1000 }));
