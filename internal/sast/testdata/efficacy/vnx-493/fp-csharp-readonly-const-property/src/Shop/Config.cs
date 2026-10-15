namespace Acme.Shop
{
    public class Config
    {
        public const string PasswordHeader = "X-Password";
        public static readonly string ApiKeyName = "key";
        public decimal Price { get; private set; }
        public string Role { get; init; }
        public string Token => _token;
        private string _token;
    }
}
