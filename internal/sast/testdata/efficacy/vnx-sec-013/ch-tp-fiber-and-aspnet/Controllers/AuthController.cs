using Microsoft.AspNetCore.Mvc;

public class AuthController : Controller
{
    [HttpPost]
    public IActionResult Login(LoginModel model)
    {
        var token = _tokens.Issue(model);
~>        Response.Cookies.Append("auth_token", token);
        return Ok();
    }
}
