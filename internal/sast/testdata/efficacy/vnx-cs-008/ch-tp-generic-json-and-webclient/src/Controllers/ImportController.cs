using Microsoft.AspNetCore.Mvc;

namespace Social.Controllers;

public class ImportController : Controller
{
    private readonly HttpClient _http;

    public ImportController(HttpClient http) => _http = http;

    [HttpPost]
    public async Task<IActionResult> FromFeed([FromForm] string feedUrl)
    {
~>        var items = await _http.GetFromJsonAsync<List<FeedItem>>(feedUrl);
        return Ok(items);
    }
}
