using System.Text;

namespace App.Keys;

public class ApiKeyGenerator
{
    private const string Alphabet = "@@sample:A[B]CD[E]FG[H]JK[L]MN[P]QR[S]TU[V]WX[Y]Za[b]cd[e]fg[h]ij[k]mn[p]qr[s]tu[v]wx[y]z2[3]45[6]78[9]@@";
    private static readonly Random Rand = new();

    public string GenerateApiKey(int length = 40)
    {
        var sb = new StringBuilder(length);
        for (var i = 0; i < length; i++)
        {
~>            sb.Append(Alphabet[Rand.Next(Alphabet.Length)]);
        }
        return sb.ToString();
    }
}
