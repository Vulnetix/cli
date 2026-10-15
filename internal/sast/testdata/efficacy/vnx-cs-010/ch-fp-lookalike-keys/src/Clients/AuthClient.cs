using System.Collections.Generic;
using System.Net.Http;

namespace Clients
{
    public sealed class AuthClient
    {
        public FormUrlEncodedContent Body(string user, string pass)
        {
            return new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = user,
                ["password"] = pass,
            });
        }

        public string Query(string user, string pass) => "?user=" + user + "&password=" + pass;

        public string Profile() => "Name=Alice;OldPassword=changed;PasswordHint=pet name";

        public string Ui() => "Server=unused;Password=;";
    }
}
