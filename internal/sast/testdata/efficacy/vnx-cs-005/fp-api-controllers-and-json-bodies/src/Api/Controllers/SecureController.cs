using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers
{
    [AutoValidateAntiforgeryToken]
    public abstract class SecureController : Controller
    {
    }
}
