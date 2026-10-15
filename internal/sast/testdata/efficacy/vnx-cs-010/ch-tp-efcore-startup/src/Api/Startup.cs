using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace Api
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ShopContext>(o =>
~>                o.UseSqlServer("Server=tcp:@@sample:s[h]op[-]sq[l][.]d[a]ta[b]as[e][.]w[i]nd[o]ws[.]ne[t]@@,1433;Initial Catalog=shop;User ID=shopadmin;Password=Sh0p!Adm1n2024;Encrypt=True;"));

            services.AddDbContext<AuditContext>(o => o.UseNpgsql(
~>                "Host=audit-pg;Port=5432;Database=audit;@@sample:U[s]er[n]am[e][=]a[u]di[t][_]w[r]it[e]r@@;@@sample:P[a]ss[w]or[d][=]A[u]d1[t][-]W[r]1t[e]r@@"));

            services.AddSingleton<IConnectionMultiplexer>(
~>                @@sample:C[o]nn[e]ct[i]on[M]ul[t]ip[l]ex[e]r[.][C]on[n]ec[t]@@("@@sample:r[e]di[s][-]p[r]im[a]ry[.]in[t]er[n]al@@:6380,ssl=true,@@sample:p[a]ss[w]or[d][=]R[d]5[-][9]fK[2]q@@,@@sample:a[b]or[t]Co[n]ne[c]t[=][f]al[s]e@@"));

            services.AddStackExchangeRedisCache(o =>
            {
~>                o.Configuration = "@@sample:s[e]ss[i]on[s][.]i[n]te[r]na[l]@@:6379,@@sample:p[a]ss[w]or[d][=]S[3]ss[1]0n[Z]@@";
            });
        }
    }
}
