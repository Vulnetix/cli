using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

// Unsigned tokens accepted by configuration: VNX-SEC-015 leaves these lines to this rule.
public static class TokenOptions
{
    public static TokenValidationParameters Lenient() => new TokenValidationParameters
    {
~>        RequireSignedTokens = false,
        ValidateAudience = false,
    };

    public static TokenValidationParameters NoCheck() => new TokenValidationParameters
    {
~>        SignatureValidator = (jwt, p) => new JwtSecurityToken(jwt),
    };

    public static TokenValidationParameters NoCheckBlock() => new TokenValidationParameters
    {
~>        SignatureValidator = (jwt, p) =>
        {
            var parsed = new JwtSecurityToken(jwt);
            return parsed;
        },
    };
}
