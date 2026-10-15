using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;

namespace Social.Controllers;

public class ImagesController : Controller
{
    private readonly HttpClient _http;
    private readonly IDistributedCache _cache;

    public ImagesController(HttpClient http, IDistributedCache cache)
    {
        _http = http;
        _cache = cache;
    }

    [HttpGet]
    public async Task<IActionResult> Proxy(string src)
    {
        if (!Uri.TryCreate(src, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || !uri.Host.EndsWith(".cdn.example.com", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest();
        }
        var bytes = await _http.GetByteArrayAsync(uri);
        return File(bytes, "image/png");
    }

    [HttpGet]
    public async Task<IActionResult> Cached(string key)
    {
        var value = await _cache.GetStringAsync(key);
        return Content(value ?? "");
    }
}
