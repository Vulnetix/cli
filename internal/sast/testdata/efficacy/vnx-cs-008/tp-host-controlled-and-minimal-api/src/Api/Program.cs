using System;
using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/fetch", async (string url, HttpClient http) =>
~>    await http.GetStringAsync(url));

app.MapGet("/status", async (HttpRequest request, HttpClient http) =>
{
    var host = request.Query["host"];
~>    var res = await http.GetAsync($"http://{host}/status");
    return Results.Ok(res.StatusCode);
});

app.MapGet("/region", async (string region, HttpClient http) =>
{
~>    return await http.GetStringAsync("https://" + region + ".internal.example.com/api");
});

app.MapGet("/relay", async (string endpoint, IHttpClientFactory factory) =>
{
    var client = factory.CreateClient();
~>    client.BaseAddress = new Uri(endpoint);
    var target = new Uri(endpoint + "/health");
~>    return await client.GetStringAsync(target);
});

app.Run();
