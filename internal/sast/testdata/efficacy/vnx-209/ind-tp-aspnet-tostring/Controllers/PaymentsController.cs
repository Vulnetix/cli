using System;
using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PaymentsController : ControllerBase
    {
        private readonly IPaymentService _payments;

        public PaymentsController(IPaymentService payments) => _payments = payments;

        [HttpPost("{id}/capture")]
        public IActionResult Capture(Guid id)
        {
            try
            {
                return Ok(_payments.Capture(id));
            }
            catch (Exception ex)
            {
~>                return StatusCode(500, ex.ToString());
            }
        }
    }
}
