using System;
using Microsoft.AspNetCore.Mvc;

public class OrdersController : Controller
{
    public IActionResult Get(int id)
    {
        try
        {
            return Ok(_orders.Find(id));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "lookup failed: {Trace}", ex.StackTrace);
            return StatusCode(500, "internal error");
        }
    }
}
