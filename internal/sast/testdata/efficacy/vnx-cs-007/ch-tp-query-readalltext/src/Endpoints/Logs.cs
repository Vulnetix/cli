namespace Ops.Endpoints;

public static class Logs
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/logs", (HttpContext ctx) =>
        {
            var file = ctx.Request.Query["file"].ToString();
~>            return Results.Text(File.ReadAllText($"/var/log/app/{file}"));
        });
    }
}
