using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

[ValidateAntiForgeryToken]
public abstract class SecureControllerBase<TService> : Controller
{
    protected TService Service { get; }

    protected SecureControllerBase(TService service) => Service = service;
}
