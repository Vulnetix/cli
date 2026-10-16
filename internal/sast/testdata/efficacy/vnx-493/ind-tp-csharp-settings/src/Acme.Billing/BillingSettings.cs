using System;

namespace Acme.Billing
{
    public class BillingSettings
    {
~>        public static string ConnectionPassword = "";
~>        public decimal Balance;
~>        public bool IsAdmin;
~>        public string ApiToken;
        public string DisplayName;
        public const string Currency = "EUR";
    }
}
