using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;

namespace Profiles.Controllers
{
    public class ProfileCacheController : Controller
    {
        private readonly IDistributedCache _cache;

        public ProfileCacheController(IDistributedCache cache) => _cache = cache;

        public async Task<IActionResult> Get(string key)
        {
            var bytes = await _cache.GetAsync(key);
            return bytes == null ? NotFound() : File(bytes, "application/json");
        }
    }
}
