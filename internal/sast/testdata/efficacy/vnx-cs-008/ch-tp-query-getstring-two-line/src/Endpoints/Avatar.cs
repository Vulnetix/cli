namespace Social.Endpoints;

public static class Avatar
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/avatar", async (HttpRequest request, IHttpClientFactory factory) =>
        {
            var target = request.Query["src"].ToString();
            var client = factory.CreateClient();
~>            var bytes = await client.GetByteArrayAsync(target);
            return Results.File(bytes, "image/png");
        });
    }
}
