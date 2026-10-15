namespace App.Accounts;

public class PasswordReset
{
    public void Begin(User user)
    {
~>        user.ResetToken = @@sample:R[a]nd[o]m[.][S]ha[r]ed[.]Ne[x]tI[n]t6[4]@@().ToString("x");
        user.ResetExpires = DateTime.UtcNow.AddHours(1);
        _mailer.SendReset(user);
    }
}
