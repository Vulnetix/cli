using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Shop.Controllers
{
    public class ItemsController : ControllerBase
    {
        private readonly ILogger<ItemsController> _logger;

        public ItemsController(ILogger<ItemsController> logger) => _logger = logger;

        public IActionResult Get()
        {
            try
            {
                return Ok(new object());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "items failed: {Trace}", ex.ToString());
                return StatusCode(500, "An unexpected error occurred.");
            }
        }
    }
}
