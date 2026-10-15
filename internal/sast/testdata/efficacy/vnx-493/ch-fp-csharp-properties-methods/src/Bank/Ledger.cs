namespace Acme.Bank
{
    public class Ledger
    {
        public decimal Balance { get; private set; }
        public string Role => _role;
        public decimal Price
        {
            get { return _price; }
        }
        public const string PasswordField = "password";
        public static readonly decimal MaxAmount = 100m;
        public bool IsAdmin() { return _admin; }
        public void SetPassword(string password) { _pw = password; }
        public event EventHandler BalanceChanged;
    }
}
