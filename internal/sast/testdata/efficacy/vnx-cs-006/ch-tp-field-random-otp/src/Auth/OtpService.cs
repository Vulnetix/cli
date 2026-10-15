namespace App.Auth;

public class OtpService
{
    private readonly Random _rng = new Random();

    public string IssueCode(string userId)
    {
~>        var code = _rng.Next(100000, 999999).ToString();
        _store.Save(userId, code, TimeSpan.FromMinutes(5));
        return code;
    }
}
