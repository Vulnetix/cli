using System.Web.Mvc;

namespace Intranet.Controllers
{
    [ValidateAntiForgeryToken]
    public abstract class SecureController : Controller
    {
    }
}
