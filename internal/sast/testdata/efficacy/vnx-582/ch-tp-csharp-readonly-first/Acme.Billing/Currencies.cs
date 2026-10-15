namespace Acme.Billing
{
    public static class Currencies
    {
~>        public readonly static string[] Supported = { "USD", "EUR", "GBP" };
~>        public static readonly decimal[] Thresholds = new decimal[] { 10m, 100m, 1000m };
    }
}
