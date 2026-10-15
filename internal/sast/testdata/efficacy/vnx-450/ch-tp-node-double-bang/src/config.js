module.exports = {
  port: Number(process.env.PORT || 3000),
~>  allowSignup: !!process.env.ALLOW_SIGNUP,
~>  skipAuth: Boolean(process.env.SKIP_AUTH),
~>  csrfEnabled: process.env.CSRF_ENABLED ?? true,
};
