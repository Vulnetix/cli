using Microsoft.AspNetCore.Http;

public class EmbedMiddleware
{
    private readonly RequestDelegate _next;

    public EmbedMiddleware(RequestDelegate next) => _next = next;

    public async Task Invoke(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
~>            context.Response.Headers.Remove("X-Frame-Options");
~>            context.Response.Headers["X-Frame-Options"] = "ALLOW-FROM https://partner.example";
            return Task.CompletedTask;
        });
        await _next(context);
    }
}
