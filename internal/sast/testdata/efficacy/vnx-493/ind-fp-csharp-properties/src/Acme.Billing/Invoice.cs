namespace Acme.Billing
{
    public class Invoice
    {
        public decimal Price { get; private set; }
        public decimal Balance => Price - Paid;
        public decimal Paid { get; init; }
        public static readonly string ApiKeyName = "x-api-key";
        public const string PasswordHeader = "X-Password";
        private string secret;
        internal bool isAdmin;

        public string GetToken() => "n/a";
    }
}
