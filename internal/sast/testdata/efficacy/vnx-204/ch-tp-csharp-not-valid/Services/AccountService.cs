using System.Threading.Tasks;

namespace Shop.Services
{
    public class AccountService
    {
        private readonly IUserStore _users;
        private readonly IHasher _hasher;

        public AccountService(IUserStore users, IHasher hasher)
        {
            _users = users;
            _hasher = hasher;
        }

        public async Task<string> SignIn(string email, string password)
        {
            var account = await _users.FindByEmailAsync(email);
            if (account == null)
            {
~>                return "Email address not found.";
            }
            if (!_hasher.Verify(account.PasswordHash, password))
            {
                return "Password not valid for this account.";
            }
            return null;
        }
    }
}
