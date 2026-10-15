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
~>            return StatusCode(500, ex.StackTrace);
        }
    }

    public IActionResult Export(int id)
    {
        try
        {
            return File(_orders.Export(id), "text/csv");
        }
        catch (Exception ex)
        {
~>            return Content(ex.ToString());
        }
    }
}
