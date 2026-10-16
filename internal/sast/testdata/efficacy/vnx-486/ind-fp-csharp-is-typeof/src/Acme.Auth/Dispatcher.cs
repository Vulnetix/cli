using Microsoft.Extensions.Logging;

namespace Acme.Auth
{
    public class Dispatcher
    {
        private readonly ILogger<Dispatcher> _log;

        public Dispatcher(ILogger<Dispatcher> log) { _log = log; }

        public bool Trusted(object caller)
        {
            _log.LogDebug("caller type {Type}", caller.GetType().Name);
            if (caller is TrustedCaller)
                return true;
            if (caller.GetType() == typeof(SystemCaller))
                return true;
            var label = $"Handled by {caller.GetType().FullName}";
            _log.LogInformation(label);
            return false;
        }
    }
}
