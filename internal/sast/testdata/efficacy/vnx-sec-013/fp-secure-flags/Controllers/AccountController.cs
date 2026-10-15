Response.Cookies.Append("auth", token, new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Strict,
});
o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
