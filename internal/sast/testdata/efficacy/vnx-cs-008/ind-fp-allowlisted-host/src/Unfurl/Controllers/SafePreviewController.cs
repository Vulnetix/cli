using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Unfurl.Controllers
{
    public class SafePreviewController : Controller
    {
        private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
        {
            "api.example.com",
            "cdn.example.com",
        };

        private readonly HttpClient _http;

        public SafePreviewController(HttpClient http) => _http = http;

        public async Task<IActionResult> Fetch(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps ||
                !AllowedHosts.Contains(uri.Host))
            {
                return BadRequest();
            }
            return Content(await _http.GetStringAsync(uri));
        }
    }
}
