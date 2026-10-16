using Microsoft.AspNetCore.Http;

namespace Acme.Web.Services;

public static class ClientAddress
{
    public static string For(HttpContext context)
    {
~>        var ip = context.Request.Headers["CF-Connecting-IP"].FirstOrDefault()
            ?? context.Connection.RemoteIpAddress?.ToString();
        return ip ?? "0.0.0.0";
    }
}
