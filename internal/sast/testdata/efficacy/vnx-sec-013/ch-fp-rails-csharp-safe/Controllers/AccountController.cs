using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    private static readonly CookieOptions AuthCookieOptions = new() { HttpOnly = true, Secure = true };

    public IActionResult Login(string token)
    {
        Response.Cookies.Append("auth_token", token, AuthCookieOptions);
        Response.Cookies.Append("auth_refresh", token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
        });
        Response.Cookies.Append("ui_theme", "dark");
        return Ok();
    }

    public IActionResult Logout()
    {
        Response.Cookies.Delete("auth_token");
        return Ok();
    }
}
