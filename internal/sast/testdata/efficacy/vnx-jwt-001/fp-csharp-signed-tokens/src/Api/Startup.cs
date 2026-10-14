using Microsoft.IdentityModel.Tokens;

public static class AuthSetup
{
    public static TokenValidationParameters Parameters(SecurityKey key) => new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        RequireSignedTokens = true,
        RequireExpirationTime = false,
    };
}
