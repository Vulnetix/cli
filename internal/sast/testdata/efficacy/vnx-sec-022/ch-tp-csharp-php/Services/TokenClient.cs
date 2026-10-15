using Microsoft.Extensions.Logging;

public class TokenClient
{
    private readonly ILogger<TokenClient> _logger;

    public void Store(TokenResponse response)
    {
~>        _logger.LogDebug("Received access token {Token}", @@sample:r[e]sp[o]ns[e][.]A[c]ce[s]sT[o]ke[n]@@);
    }
}
