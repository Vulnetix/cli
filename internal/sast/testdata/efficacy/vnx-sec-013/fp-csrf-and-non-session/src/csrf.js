// The SPA reads this token from JavaScript, so it is deliberately not httpOnly.
res.cookie('XSRF-TOKEN', req.csrfToken(), { httpOnly: false, secure: true });
res.cookie('theme', 'dark');
res.cookie('lang', req.query.lang, { maxAge: 31536000 });
