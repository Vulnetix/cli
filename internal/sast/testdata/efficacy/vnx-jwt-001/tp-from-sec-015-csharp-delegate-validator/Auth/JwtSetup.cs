using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

public static class JwtSetup
{
    public static TokenValidationParameters Parameters() => new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = "https://auth.acme.io",
~>        SignatureValidator = delegate (string token, TokenValidationParameters p)
        {
            return new JwtSecurityToken(token);
        },
    };
}
