using RestSharp;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
var app = builder.Build();

app.MapGet("/probe", async ([FromQuery] string endpoint, IHttpClientFactory factory) =>
{
    var client = factory.CreateClient();
~>    client.BaseAddress = new Uri(endpoint);
    var res = await client.GetAsync("/status");
    return Results.Ok((int)res.StatusCode);
});

app.MapPost("/replay", async (string target) =>
{
~>    var rest = new RestClient(target);
    var res = await rest.ExecuteAsync(new RestRequest("/"));
    return Results.Ok(res.StatusCode);
});

app.Run();
