using System;
using System.Threading.Tasks;

namespace Identity
{
    public class PasswordResetService
    {
        private readonly Random _random = new Random();
        private readonly IUserStore _users;

        public PasswordResetService(IUserStore users) => _users = users;

        public async Task<string> GenerateResetCodeAsync(string email)
        {
~>            var code = _random.Next(100000, 999999).ToString("D6");
            await _users.SaveResetCodeAsync(email, code, DateTime.UtcNow.AddMinutes(15));
            return code;
        }

        public string IssueOtp()
        {
~>            return Random.Shared.Next(0, 1_000_000).ToString("D6");
        }
    }
}
