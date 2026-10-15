using Microsoft.AspNetCore.Mvc;

namespace Social.Controllers;

public class PreviewController : Controller
{
    private readonly HttpClient _httpClient;

    public PreviewController(HttpClient httpClient) => _httpClient = httpClient;

    [HttpGet]
    public async Task<IActionResult> Fetch(string url)
    {
~>        var resp = await _httpClient.GetAsync(url);
        return Content(await resp.Content.ReadAsStringAsync());
    }
}
