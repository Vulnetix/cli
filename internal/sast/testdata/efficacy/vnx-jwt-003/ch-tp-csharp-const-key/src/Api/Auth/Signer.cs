using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Api.Auth
{
    public class Signer
    {
~>        private const string SigningKey = "@@sample:p[9]X2[k]Lq[7]Rt[4]vW[z]8n[B]3m[C]6d[F]1@@";

        public SigningCredentials Credentials() =>
            new SigningCredentials(new SymmetricSecurityKey(@@sample:E[n]co[d]in[g][.]U[T]F8[.]Ge[t]By[t]es@@(SigningKey)), @@sample:S[e]cu[r]it[y]Al[g]or[i]th[m]s[.][H]ma[c]Sh[a]25[6]@@);
    }
}
