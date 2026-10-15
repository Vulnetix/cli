using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Api.Auth
{
    public class TokenService
    {
        public SigningCredentials Credentials()
        {
~>            var key = new @@sample:S[y]mm[e]tr[i]cS[e]cu[r]it[y]Ke[y]@@(@@sample:E[n]co[d]in[g][.]U[T]F8[.]Ge[t]By[t]es@@("@@sample:T[h]is[I]sM[y]Ve[r]yS[e]cr[e]tS[i]gn[i]ng[K]ey[9]87@@"));
            return new SigningCredentials(key, @@sample:S[e]cu[r]it[y]Al[g]or[i]th[m]s[.][H]ma[c]Sh[a]25[6]@@);
        }
    }
}
