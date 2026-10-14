using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class ImportController : Controller
    {
        private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase) { "feeds.example.com" };
        private readonly HttpClient _client;

        public async Task<IActionResult> Import(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !AllowedHosts.Contains(uri.Host))
            {
                return BadRequest();
            }
            var data = await _client.GetStringAsync(uri);
            return Ok(data);
        }

        public async Task<IActionResult> Mirror(string source)
        {
            if (!IsAllowedUrl(source))
            {
                return BadRequest();
            }
            return Ok(await _client.GetStringAsync(source));
        }

        private static bool IsAllowedUrl(string value) => value.StartsWith("https://feeds.example.com/", StringComparison.Ordinal);
    }
}
