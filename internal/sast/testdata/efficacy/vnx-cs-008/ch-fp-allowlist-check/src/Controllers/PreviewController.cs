using Microsoft.AspNetCore.Mvc;

namespace Social.Controllers;

public class PreviewController : Controller
{
    private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase) { "images.example.com", "cdn.example.com" };
    private readonly HttpClient _httpClient;

    public PreviewController(HttpClient httpClient) => _httpClient = httpClient;

    [HttpGet]
    public async Task<IActionResult> Fetch(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !AllowedHosts.Contains(uri.Host))
        {
            return BadRequest();
        }
        var resp = await _httpClient.GetAsync(uri);
        return Content(await resp.Content.ReadAsStringAsync());
    }
}
