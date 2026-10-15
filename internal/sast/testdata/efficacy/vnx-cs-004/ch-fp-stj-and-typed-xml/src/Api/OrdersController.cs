using System.IO;
using System.Text.Json;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace App.Api;

public class OrdersController : Controller
{
    [HttpPost]
    public IActionResult Create([FromBody] string body)
    {
        var order = JsonSerializer.Deserialize<Order>(body);
        return Ok(order);
    }

    public Order FromXml(Stream s)
    {
        var xs = new XmlSerializer(typeof(Order));
        return (Order)xs.Deserialize(s);
    }

    public Order FromJson(string body) => Newtonsoft.Json.JsonConvert.DeserializeObject<Order>(body);
}
