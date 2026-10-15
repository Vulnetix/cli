using Flurl;
using Flurl.Http;
using Microsoft.AspNetCore.Mvc;

namespace Weather.Controllers
{
    public class WeatherController : Controller
    {
        private const string ApiBase = "https://api.weather.example";

        [HttpGet]
        public async Task<IActionResult> City(string city)
        {
            var json = await ApiBase
                .AppendPathSegment("v1/forecast")
                .SetQueryParam("city", city)
                .GetStringAsync();
            return Content(json, "application/json");
        }

        [HttpGet]
        public async Task<IActionResult> Station(string id)
        {
            var data = await "https://api.weather.example/stations"
                .AppendPathSegment(id)
                .GetJsonAsync<Station>();
            return Json(data);
        }
    }
}
