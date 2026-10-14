namespace Shop.Core;

public static class AuthorizationConstants
{
~>    public const string JWT_SECRET_KEY = "SecretKeyThatIsLongEnoughForHmac";
}

public static class Signing
{
    public static SymmetricSecurityKey Key() =>
~>        new SymmetricSecurityKey(Encoding.UTF8.GetBytes("inline-signing-key-value"));
}
