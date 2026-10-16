var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var root = Path.Combine(app.Environment.ContentRootPath, "assets");

~>app.MapGet("/assets/{name}", (string name) => Results.File(Path.Combine(root, name), "application/octet-stream"));

app.MapDelete("/cache", ([FromQuery] string key) =>
{
~>    File.Delete(Path.Combine(root, "cache", key));
    return Results.NoContent();
});

app.Run();
