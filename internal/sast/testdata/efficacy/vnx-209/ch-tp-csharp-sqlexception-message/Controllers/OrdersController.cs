using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Shop.Controllers
{
    [ApiController]
    [Route("api/orders")]
    public class OrdersController : ControllerBase
    {
        [HttpGet("{id}")]
        public IActionResult Get(int id)
        {
            try
            {
                return Ok(Load(id));
            }
            catch (SqlException ex)
            {
~>                return StatusCode(500, ex.Message);
            }
        }

        private object Load(int id) => new object();
    }
}
