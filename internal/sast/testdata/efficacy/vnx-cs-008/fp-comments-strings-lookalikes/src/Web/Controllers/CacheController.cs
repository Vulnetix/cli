using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;

namespace Web.Controllers
{
    public class CacheController : Controller
    {
        private readonly IDistributedCache _cache;
        private readonly HttpClient _client;

        // Never call _client.GetAsync(Request.Query["url"]) directly.
        public async Task<IActionResult> Get(string key)
        {
            /* new WebClient().DownloadString(Request.Query["u"]) is SSRF */
            var value = await _cache.GetAsync(key);
            var item = await _cache.GetStringAsync(Request.Query["k"]);
            _logger.LogInformation("client.GetAsync(url) skipped for {Key}", key);
            var page = await _client.GetStringAsync("https://example.com/help?topic=GetAsync(url)");
            return Ok(value);
        }
    }
}
