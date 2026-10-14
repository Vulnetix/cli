using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var root = "/srv/files";

app.MapGet("/files/{name}", (string name) =>
~>    Results.File(Path.Combine(root, name)));

app.MapPost("/upload", async (IFormFile file) =>
{
~>    var dest = Path.Combine(root, "uploads", file.FileName);
    using var stream = new FileStream(dest, FileMode.Create);
    await file.CopyToAsync(stream);
    return Results.Ok();
});

app.MapPost("/upload2", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    foreach (var upload in form.Files)
    {
~>        using var output = File.Create("/srv/files/inbox/" + upload.FileName);
        await upload.CopyToAsync(output);
    }
    return Results.Ok();
});

app.Run();
