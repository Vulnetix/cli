using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class BillingController : SecureControllerBase
    {
        [HttpPost]
        public IActionResult Cancel(int subscriptionId)
        {
            return RedirectToAction("Index");
        }
    }

    public class WebhookEndpoint : JsonEndpointBase
    {
        [HttpPost("hooks/stripe")]
        public IActionResult Receive() => Ok();
    }
}
