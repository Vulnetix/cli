using Microsoft.AspNetCore.Mvc;

public class AuthController : Controller
{
    public IActionResult Login(string token)
    {
        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        };
        Response.Cookies.Append("auth_token", token, options);
        return Ok();
    }
}
