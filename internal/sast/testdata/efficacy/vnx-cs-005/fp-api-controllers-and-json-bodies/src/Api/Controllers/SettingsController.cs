using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers
{
    public class SettingsController : SecureController
    {
        [HttpPost]
        public IActionResult Save(SettingsModel model)
        {
            SettingsStore.Save(model);
            return RedirectToAction("Index");
        }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class OrdersController : ControllerBase
    {
        [HttpPost]
        public IActionResult Create(OrderDto order) => Ok(order);
    }

    [Route("api/tokens")]
    public class TokensController : ControllerBase
    {
        [HttpPost]
        public IActionResult Issue(LoginDto login) => Ok();
    }

    public class ImportController : Controller
    {
        [HttpPost]
        [Consumes("application/json")]
        public IActionResult Import(ImportDto body) => Ok();

        [HttpPost]
        public IActionResult Upload([FromBody] UploadDto body) => Ok();
    }
}
