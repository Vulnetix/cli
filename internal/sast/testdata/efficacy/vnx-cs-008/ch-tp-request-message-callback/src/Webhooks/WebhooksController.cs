using Microsoft.AspNetCore.Mvc;

namespace Hooks.Webhooks;

public class WebhooksController : Controller
{
    private readonly HttpClient _client;

    public WebhooksController(HttpClient client) => _client = client;

    [HttpPost]
    public async Task<IActionResult> Test([FromForm] string callbackUrl)
    {
~>        using var message = new HttpRequestMessage(HttpMethod.Post, callbackUrl)
        {
            Content = new StringContent("{\"ping\":true}"),
        };
        var resp = await _client.SendAsync(message);
        return StatusCode((int)resp.StatusCode);
    }
}
