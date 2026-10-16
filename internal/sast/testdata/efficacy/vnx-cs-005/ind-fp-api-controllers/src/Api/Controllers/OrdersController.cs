using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class OrdersController : ControllerBase
    {
        private readonly IOrderService _orders;

        public OrdersController(IOrderService orders) => _orders = orders;

        [HttpPost]
        public IActionResult Create(CreateOrder request)
        {
            var id = _orders.Create(request);
            return CreatedAtAction(nameof(Get), new { id }, null);
        }

        [HttpGet("{id}")]
        public IActionResult Get(int id) => Ok(_orders.Find(id));

        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            _orders.Delete(id);
            return NoContent();
        }
    }
}
