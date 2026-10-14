using Microsoft.Extensions.Configuration;

namespace Data
{
    /// <summary>
    /// Reads the connection string. Format:
    /// "Server=myServer;Database=myDb;User Id=myUser;Password=myPass;"
    /// </summary>
    public static class Connections
    {
        // Old: "Server=old-sql;Database=Hr;User Id=sa;Password=OldPass1;"
        /* "Host=pg;Username=app;Password=Pg-Pass-1;Database=app" */
        public static string Read(IConfiguration config) => config.GetConnectionString("Hr")!;
    }
}
