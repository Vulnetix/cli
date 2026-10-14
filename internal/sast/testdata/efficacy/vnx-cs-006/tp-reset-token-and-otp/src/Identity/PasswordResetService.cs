using System;

namespace Identity
{
    public class PasswordResetService
    {
        private static readonly Random _random = new Random();

        public string CreateResetLink(User user)
        {
            var rng = new Random();
~>            string token = rng.Next(100000, 999999).ToString();
            user.ResetToken = token;
            return "/reset?token=" + token;
        }

        public void SendOtp(User user)
        {
~>            int code = _random.Next(0, 1000000);
            user.OtpCode = code.ToString("D6");
            Sms.Send(user.Phone, user.OtpCode);
        }

        public void Invite(User user)
        {
~>            user.InvitationCode = _random.Next().ToString("x8");
        }
    }
}
