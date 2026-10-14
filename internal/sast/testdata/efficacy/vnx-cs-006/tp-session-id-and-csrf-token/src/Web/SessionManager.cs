using System;

namespace Web
{
    public class SessionManager
    {
        private readonly Random _rng = new();

        public Session Start(User user)
        {
            var session = new Session
            {
                UserId = user.Id,
~>                SessionId = _rng.NextInt64().ToString("x16"),
            };
~>            session.CsrfToken = Convert.ToHexString(BitConverter.GetBytes(_rng.NextDouble()));
            return session;
        }
    }
}
