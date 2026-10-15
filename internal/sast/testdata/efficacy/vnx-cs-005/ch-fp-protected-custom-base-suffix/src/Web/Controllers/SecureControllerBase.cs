using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    [AutoValidateAntiforgeryToken]
    public abstract class SecureControllerBase : Controller
    {
    }

    public abstract class JsonEndpointBase : ControllerBase
    {
    }
}
