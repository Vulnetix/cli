using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Api.Auth
{
    public class Keys
    {
        public SymmetricSecurityKey From(IConfiguration config) =>
            new SymmetricSecurityKey(@@sample:E[n]co[d]in[g][.]U[T]F8[.]Ge[t]By[t]es@@(config["Jwt:Key"]));
    }
}
