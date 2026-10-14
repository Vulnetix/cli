public static class Signing
{
    public static SymmetricSecurityKey Key(IConfiguration config) =>
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));

    public const string JWT_SECRET_SETTING = "Jwt:Key";
}
