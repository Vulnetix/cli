public class AccountController : Controller
{
    public IActionResult Login(string token)
    {
        Response.Cookies.Append("auth", token, new CookieOptions
        {
~>            HttpOnly = false,
~>            Secure = false,
        });
        services.ConfigureApplicationCookie(o =>
        {
~>            o.Cookie.SecurePolicy = CookieSecurePolicy.None;
        });
        return Ok();
    }
}
