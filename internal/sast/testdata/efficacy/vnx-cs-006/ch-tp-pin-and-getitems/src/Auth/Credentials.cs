namespace App.Auth;

public static class Credentials
{
    private static readonly char[] Chars = "@@sample:a[b]cd[e]fg[h]ij[k]lm[n]op[q]rs[t]uv[w]xy[z]01[2]34[5]67[8]9@@".ToCharArray();

    public static int NewPin(Random rnd)
    {
~>        int pin = rnd.Next(0, 10000);
        return pin;
    }

    public static string NewInviteCode() =>
~>        new string(Random.Shared.GetItems(Chars, 12));
}
