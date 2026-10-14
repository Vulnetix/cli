using Microsoft.Extensions.Logging;

namespace Payments.Crypto
{
    /// <summary>
    /// Crypto policy. Do not call MD5.Create() or new DESCryptoServiceProvider();
    /// use SHA256.Create() and Aes.Create() instead.
    /// </summary>
    public sealed class Policy
    {
        private readonly ILogger<Policy> _log;

        public Policy(ILogger<Policy> log) => _log = log;

        // Previously: using var md5 = MD5.Create();
        /* var des = new TripleDESCryptoServiceProvider(); */

        public void Warn()
        {
            _log.LogWarning("MD5.Create() and SHA1.HashData() are rejected by policy");
            _log.LogWarning(@"HashAlgorithm.Create(""MD5"") is not allowed");
            var hint = $"Replace {nameof(Policy)}: new SHA1Managed() -> SHA256.Create()";
            _log.LogInformation(hint);
        }
    }
}
