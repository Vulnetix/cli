using Microsoft.AspNetCore.Mvc;

public class LoginController : Controller
{
    private string ClientIp()
    {
~>        var ip = Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (string.IsNullOrEmpty(ip))
        {
            ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        }
        return ip;
    }
}
