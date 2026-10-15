using System;

namespace Acme.Auth
{
    public class Audit
    {
        public void Record(object principal)
        {
            _log.Info($"principal type {principal.GetType().Name}");
            if (principal.GetType() == typeof(AdminPrincipal))
                Grant();
            if (principal is ServicePrincipal sp)
                Grant();
            var key = principal.GetType().FullName;
            _cache[key] = DateTime.UtcNow;
            if (user.Name == "admin")
                Grant();
        }
    }
}
