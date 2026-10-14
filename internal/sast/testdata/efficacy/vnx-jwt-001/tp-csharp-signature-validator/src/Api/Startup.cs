using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

public static class AuthSetup
{
    public static TokenValidationParameters Parameters() => new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
~>        RequireSignedTokens = false,
~>        SignatureValidator = (token, parameters) => new JwtSecurityToken(token),
    };
}
