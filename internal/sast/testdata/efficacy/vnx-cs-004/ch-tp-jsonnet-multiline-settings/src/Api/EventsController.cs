using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace App.Api;

public class EventsController : Controller
{
    [HttpPost]
    public IActionResult Ingest([FromBody] string payload)
    {
        var evt = JsonConvert.DeserializeObject<object>(payload, new JsonSerializerSettings
        {
~>            TypeNameHandling = TypeNameHandling.Auto,
        });
        return Ok(evt);
    }

    private static readonly JsonSerializer Serializer = new JsonSerializer
    {
~>        TypeNameHandling = TypeNameHandling.All
    };
}
