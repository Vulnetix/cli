using Microsoft.AspNetCore.Mvc;

public class AuthController : Controller
{
    public IActionResult Login(string token)
    {
        var options = new CookieOptions
        {
~>            HttpOnly = false,
            Expires = DateTimeOffset.UtcNow.AddHours(8)
        };
        Response.Cookies.Append("auth_token", token, options);
        return Ok();
    }
}
