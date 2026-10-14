using System.Diagnostics;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

~>app.MapGet("/run", (string tool) => Process.Start(tool, "--version"));

app.MapPost("/zip", (string folder) =>
{
~>    Process.Start("bash", "-c \"zip -r out.zip " + folder + "\"");
    return Results.Ok();
});

app.Run();
