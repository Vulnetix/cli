using Microsoft.IdentityModel.Tokens;

public static class Strict
{
    public static TokenValidationParameters Parameters(SecurityKey key) => new TokenValidationParameters
    {
        RequireSignedTokens = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidAlgorithms = new[] { @@sample:S[e]cu[r]it[y]Al[g]or[i]th[m]s[.][R]sa[S]ha[2]56@@ },
    };
}
